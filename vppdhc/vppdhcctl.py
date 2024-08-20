import asyncio
import typer # pylint: disable=import-error

app = typer.Typer()

async def send_command(socket_path, command):
    reader, writer = await asyncio.open_unix_connection(socket_path)
    writer.write(command.encode())
    await writer.drain()
    response = await reader.read(100)
    if response:
        print(f'{response.decode()}')
    writer.close()
    await writer.wait_closed()

@app.command()
def main(command: list[str] = typer.Argument(None, help="Arguments passed to the command")):
    '''Send a command to the VPPDHC control server'''
    socket_path = '/tmp/vppdhcd.sock'
    command = ' '.join(command)
    asyncio.run(send_command(socket_path, command))

if __name__ == '__main__':
    app()
