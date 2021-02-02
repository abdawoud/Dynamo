import logging

import zmq

from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit
from src.content_provider_fuzzing.server_ipc.connection_to_fuzzer import ConnectionToFuzzer


class ZeroMqServer(ConnectionToFuzzer, ExecutionUnit):
    IP_ADDRESS = '127.0.0.1'
    PORT_NUMBER = 54238

    def __init__(self):
        super().__init__()
        self._logger = logging.getLogger(__name__)

        self._context = None
        self._zmq_socket = None

    def setup(self):
        self._context = zmq.Context()
        self._zmq_socket = self._context.socket(zmq.REP)

    def run(self):
        self._zmq_socket.bind(f"tcp://{self.IP_ADDRESS}:{self.PORT_NUMBER}")

    def cleanup(self):
        self._context.destroy()

    def receive_message(self):
        return self._zmq_socket.recv().decode(encoding='utf-8')

    def send_message(self, message: str):
        self._zmq_socket.send(message.encode(encoding='utf-8'))
