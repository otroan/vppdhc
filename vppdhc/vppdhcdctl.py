# pylint: disable=import-error, invalid-name, logging-fstring-interpolation

import logging
import asyncio
from typing import Any
import os
import signal

logger = logging.getLogger(__name__)

command_registry = {}

def register_command(module, command):
    logger.debug(f'Registering command: {module} {command}')
    def decorator(func):
        if module not in command_registry:
            command_registry[module] = {}
        command_registry[module][command] = func
        return func
    return decorator

# Example module 1
@register_command('module1', 'hello')
def command_hello(args):
    return f"Hello, {args}"

async def handle_client(reader, writer):
    # Receive data from the client
    data = await reader.read(100)
    message = data.decode()
    print('Received:', message)
    parts = message.split()
    module = parts[0] if len(parts) > 0 else None
    command = parts[1] if len(parts) > 1 else None
    args = parts[2:] if len(parts) > 2 else []
    print(f"Module: {module}, Command: {command}, Args: {args}")
    try:
        response = command_registry[module][command](*args)
    except KeyError:
        response = f"Unknown command: {command!r}"

    writer.write(response.encode())
    await writer.drain()

    writer.close()
    await writer.wait_closed()

class VPPDHCD():
    def __init__(self, socket_path):
        self.socket_path = socket_path

    async def start_control_server(self):
        # Cleanup any existing socket file
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        server = await asyncio.start_unix_server(handle_client, path=self.socket_path)

        # # Handle server shutdown signals
        # loop = asyncio.get_running_loop()
        # loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.create_task(server.close()))
        # loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(server.close()))

        # logger.debug('Control server started...')
        # await server.serve_forever()
