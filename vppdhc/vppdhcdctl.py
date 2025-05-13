# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

import asyncio
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

command_registry = {}


def register_command(module: str, command: str) -> callable:
    """Register a command decorator."""
    logger.debug("Registering command: %s %s", module, command)

    def decorator(func: callable) -> callable:
        if module not in command_registry:
            command_registry[module] = {}
        command_registry[module][command] = func
        return func

    return decorator


async def handle_client(reader, writer) -> None:
    """Handle a client."""
    data = await reader.read()
    message = data.decode()
    parts = message.split()
    module = parts[0] if len(parts) > 0 else None
    command = parts[1] if len(parts) > 1 else None
    args = parts[2:] if len(parts) > 2 else []
    try:
        response = command_registry[module][command](*args)
    except KeyError:
        response = f"Unknown command: {command!r}"

    writer.write(response.encode())
    await writer.drain()

    writer.close()
    await writer.wait_closed()


class VPPDHCD:
    """VPPDHCD Control Daemon."""

    def __init__(self, socket_path) -> None:
        """VPPDHC Control Daemon."""
        self.socket_path = socket_path

    async def start_control_server(self) -> None:
        """Man entry point."""
        if Path(self.socket_path).exists():
            Path(self.socket_path).unlink()

        _ = await asyncio.start_unix_server(handle_client, path=self.socket_path)
