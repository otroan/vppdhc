#!/usr/bin/env python3

import json
import sys
from collections import defaultdict
from collections.abc import Callable
from threading import Lock
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, create_model


# Root model
class RootModel(BaseModel):
    pass


class RootModelBuilder:
    """Singleton builder for dynamically constructing and extending a root Pydantic model."""

    _instance = None
    _lock = Lock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:  # Double-checked locking for thread safety
                    cls._instance = super(RootModelBuilder, cls).__new__(cls)
                    cls._instance.fields = {}  # Initialize fields only once
                    cls._instance.root_model = create_model("RootModel")  # Start with an empty root model
        return cls._instance

    def register_model(self, key: str, model: type[BaseModel]):
        """Register a Pydantic model under a specific key and dynamically update the root model."""
        print("REGISTERING MODEL:", key, model)
        if key in self.fields:
            raise ValueError(f"Key '{key}' is already registered.")
        self.fields[key] = model

        # Dynamically rebuild the root model with the new field
        self.root_model = create_model(
            "RootModel",
            **{key: (field, None) for key, field in self.fields.items()},
        )

    def get_root_model(self) -> type[BaseModel]:
        """Return the current root model."""
        return self.root_model


def register_vppdb_model(key: str):
    """Class decorator to register a Pydantic BaseModel with the singleton RootModelBuilder.

    :param key: The hierarchical key under which the model will be registered.
    """

    def decorator(cls):
        if not issubclass(cls, BaseModel):
            raise ValueError(f"Class {cls.__name__} must inherit from Pydantic's BaseModel.")
        builder = RootModelBuilder()  # Access the singleton instance
        builder.register_model(key, cls)
        return cls

    return decorator


@register_vppdb_model("ops")
class Operational(BaseModel):
    """Operational data model."""

    model_config = ConfigDict(extra="allow")


class VPPDB:
    def __init__(self, model: Any = None):
        builder = RootModelBuilder()
        RootModel = builder.get_root_model()

        self.store = RootModel()
        self.store.ops = {}
        self.subscribers = defaultdict(list)

    def dump(self):
        print(self.store.model_dump_json(indent=4))

    def set(self, key: str, value: Any) -> None:
        segments = key.strip("/").split("/")
        current = self.store

        for i, segment in enumerate(segments):
            if i == len(segments) - 1:  # Last segment, set the value
                if isinstance(current, dict):
                    current[segment] = value
                elif isinstance(current, list):
                    index = int(segment)  # Convert the segment to an integer index
                    if index >= len(current):
                        raise IndexError(f"Index {index} is out of range for list.")
                    current[index] = value
                elif isinstance(current, BaseModel):
                    # Allow dynamic creation for models with extra="allow"
                    if type(current).model_config.get("extra") == "allow":
                        current.__dict__[segment] = value
                    elif not hasattr(current, segment):
                        raise KeyError(f"Field '{segment}' not found in {current.__class__.__name__}.")
                    else:
                        setattr(current, segment, value)
                else:
                    raise KeyError(f"Cannot set field '{segment}' on a non-object value.")
            elif isinstance(current, dict):
                if segment not in current:
                    current[segment] = {}  # Dynamically create a dictionary
                current = current[segment]
            elif isinstance(current, list):
                index = int(segment)  # Convert the segment to an integer index
                if index >= len(current):
                    raise IndexError(f"Index {index} is out of range for list.")
                current = current[index]
            elif isinstance(current, BaseModel):
                if not hasattr(current, segment):
                    # Dynamically create intermediate objects for models with extra="allow"
                    if type(current).model_config.get("extra") == "allow":
                        setattr(current, segment, {})
                    else:
                        raise KeyError(f"Field '{segment}' not found in {current.__class__.__name__}.")
                current = getattr(current, segment)
            else:
                raise KeyError(f"Cannot navigate field '{segment}' on a non-object value.")
        self.notify_subscribers(key, value)

    def subscribe(self, pointer: str, callback: Callable[[str, Any], None]) -> None:
        """Subscribe to changes on a specific key."""
        self.subscribers[pointer].append(callback)

    def notify_subscribers(self, pointer: str, value: Any):
        """Notify subscribers about a key change."""
        ptr = pointer
        while ptr:
            print(f"Checking: {ptr}")
            if ptr in self.subscribers:
                for callback in self.subscribers[ptr]:
                    callback(pointer, value)
                break  # Notify only the first subscriber
            ptr = ptr.rsplit("/", 1)[0]

    def get(self, key: str) -> Any:
        """Retrieve a value from the model hierarchy based on an implicit key.

        :param key: A slash-separated key (e.g., "nested/sub_key" or "items/0")
        :return: The value corresponding to the key, or None if the key is invalid.
        """
        segments = key.strip("/").split("/")
        current = self.store

        for segment in segments:
            if isinstance(current, list):  # Handle list indexing
                try:
                    current = current[int(segment)]
                except (ValueError, IndexError):
                    raise KeyError(f"Invalid index '{segment}' for list.")
            elif isinstance(current, BaseModel):  # Handle Pydantic objects
                if not hasattr(current, segment):
                    raise KeyError(f"Field '{segment}' not found in {current.__class__.__name__}.")
                current = getattr(current, segment)
            else:
                raise KeyError(f"Cannot navigate field '{segment}' on a non-object value.")

        return current

    # def get(self, pointer):
    #     if pointer in self.store:
    #         return self.store[pointer]
    #     ptr = pointer
    #     node = None
    #     suffix = []
    #     while ptr:
    #         if ptr in self.store:
    #             return self.store[ptr]
    #         # Split on the last /
    #         ptr, last = ptr.rsplit("/", 1)
    #         suffix.append(last)
    #         if ptr in self.store:
    #             node = self.store[ptr]
    #             for s in reversed(suffix):
    #                 if isinstance(node, dict):
    #                     node = node.get(s)
    #                 elif isinstance(node, list):
    #                     try:
    #                         index = int(s)
    #                         node = node[index]
    #                     except (ValueError, IndexError):
    #                         raise KeyError(f"Invalid list index or path: {pointer}")
    #                 else:
    #                     raise KeyError(f"Path '{pointer}' not found")
    #             break
    #     if node is None:
    #         raise KeyError(f"Path '{pointer}' not found")
    #     return node

    def find_children(self, parent_pointer):
        parent_len = len(parent_pointer)
        children = []
        for key in self.store:
            if key.startswith(parent_pointer) and key != parent_pointer:
                suffix = key[parent_len:]
                if "/" not in suffix.strip("/"):  # No further nested '/' indicates a direct child
                    children.append(key)
        return children

    # Dynamic navigation
    def resolve_implied_key(model, path):
        keys = path.strip("/").split("/")
        for key in keys:
            if key.isdigit():
                model = model[int(key)]  # Handle list indices
            else:
                model = getattr(model, key)
        return model


# Example usage
if __name__ == "__main__":
    from vppdhc.raadv import ConfIP6NDPrefix, ConfIP6NDRA

    @register_vppdb_model("system")
    class ConfSystem(BaseModel):
        """Global configuration."""

        model_config = ConfigDict(populate_by_name=True)
        bypass_tenant: int = Field(alias="bypass-tenant")
        log_level: str = Field(alias="log-level")
        log_file: str = Field(alias="log-file", default=None)

    @register_vppdb_model("dhc4test")
    class ConfDHC4ClientTest(BaseModel):
        """DHCPv4 client configuration."""

        model_config = ConfigDict(populate_by_name=True)
        interface: str

    def callback(pointer, value):
        print(f"Callback: {pointer} changed to: {value}")

    def callback2(pointer, value):
        print(f"Callback2: {pointer} changed to: {value}")

    def callback3(pointer, value):
        print(f"Callback3: {pointer} changed to: {value}")

    dhc4_config = ConfDHC4ClientTest(interface="eth0")
    ndra_config = ConfIP6NDRA(interfaces=["eth0", "eth1"], pio=[ConfIP6NDPrefix(prefix="2001:db8::/64")])
    system_config = ConfSystem(log_level="DEBUG", bypass_tenant=2000)

    # builder = RootModelBuilder()
    # RootModel = builder.get_root_model()
    # print('ROOTMODEL', RootModel, RootModel.__fields__)
    # embed()
    # model = register_plugin("dhc4client", RootModel, ConfDHC4ClientTest)
    # cdb = VPPDB(dhc4_config)
    # cdb = VPPDB(RootModel)
    cdb = VPPDB()

    # cdb = VPPDB(client_config)

    print("STORE:", cdb.store)
    cdb.set("dhc4test", dhc4_config)
    cdb.set("system", system_config)
    print("STORE:", cdb.store)

    print(cdb.get("/system/bypass_tenant"))  # Output: "value1"

    sys.exit(0)

    print(cdb.get("/ip6ndra/interfaces/1"))  # Output: "value1"
    cdb.set("/ip6ndra/interfaces/1", "updated interface")
    ip6nd = cdb.get("/ip6ndra/interfaces")
    print("IPV6 ND OBJECT:", ip6nd)
    ip6nd.append("new interface")
    print("STORE:", cdb.store)

    cdb.subscribe("/root", callback)
    cdb.subscribe("/root/child/child", callback2)
    cdb.subscribe("/root/child/chil", callback3)
    cdb.set("/root/child", "value")
    cdb.set("/root/child/grandchild", "new value")

    cdb.set(
        "/root/child/child",
        [
            {"bar": "value1"},
            {"bar": "value2"},
        ],
    )

    print(cdb.get("/root/child"))  # Output: "value1"
    print(cdb.get("/root/child/child/0"))  # Output: "value1"
    print(cdb.get("/root/child/child/1"))  # Output: "value1"
    print(cdb.get("/root/child/child/0/bar"))
    print(cdb.get("/root/child/child/1/bar"))

    data = """
        {
        "system": {
            "log-level": "debug",
            "bypass-tenant": 2000
        },
        "vpp": {
                "socket": "/var/run/vpp/punt.sock"
        },
        "dhc6client": {
            "interface": "TenGigabitEthernet8/0/0",
            "ia_na": true,
            "ia_pd": false
        },
        "nat44": {
            "pool": "/dhc4client/TenGigabitEthernet8/0/0"
        },
        "nptv6": {
            "outside-prefix": "/dhc6client/ia_pd",
            "inside-prefix": "2001:db8::/48"
        }
    }
    """
    cdb.load_json(json.loads(data))
    print("DHC6: ", cdb.find_children("/dhc6client"))
    x = json.dumps(cdb.store, indent=4)
    print(x)

    # Dynamically create paths in the Operational subtree
    cdb.set("ops/interface1/status", "up")
    cdb.set("ops/interface1/traffic", {"rx": 1000, "tx": 500})
    cdb.set("ops/interface2/status", "down")
    cdb.set("ops/interface2/errors", 5)

    # Retrieve values
    print("Interface1 Status:", cdb.get("ops/interface1/status"))
    print("Interface1 Traffic:", cdb.get("ops/interface1/traffic"))
    print("Interface2 Status:", cdb.get("ops/interface2/status"))
    print("Interface2 Errors:", cdb.get("ops/interface2/errors"))

    # Print the entire Operational subtree
    print("Operational Subtree:", cdb.get("ops"))
