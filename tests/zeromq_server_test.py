
import zmq

from src.content_provider_fuzzing.server_ipc.zeromq_server import ZeroMqServer


def test_echo_ready_message():
    server = ZeroMqServer()
    server.setup()
    server.run()

    expected_message = 'Ready'
    send_message_to_server(ZeroMqServer.PORT_NUMBER, expected_message)

    message = server.receive_message()
    assert message == expected_message

    server.cleanup()


def send_message_to_server(server_port: int, message: str):
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect(f"tcp://localhost:{server_port}")

    socket.send(message.encode(encoding='utf-8'))
