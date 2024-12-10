import asyncio
from typing import Any
import logging

logger = logging.getLogger(__name__)

class EventManager:
    def __init__(self):
        self.subscribers = {}

    def subscribe(self, event_name: str, callback) -> None:
        """Subscribe to an event with a callback."""
        if event_name not in self.subscribers:
            self.subscribers[event_name] = []
        self.subscribers[event_name].append(callback)

    async def publish(self, event_name: str, data: Any) -> None:
        """Asynchronously notify all subscribers of an event."""
        logger.debug("Publishing event %s", event_name)
        if event_name in self.subscribers:
            tasks = [asyncio.create_task(callback(data)) for callback in self.subscribers[event_name]]
            await asyncio.gather(*tasks)
