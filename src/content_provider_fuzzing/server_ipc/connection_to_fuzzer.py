import logging
from abc import ABC, abstractmethod


class CannotConnectToFuzzer(Exception):
    pass


class ConnectionToFuzzer(ABC):
    MESSAGE_ACK = 'Ack'
    MESSAGE_CRASH = 'Crash'
    MESSAGE_READY = 'Ready'
    _MESSAGE_KILL = 'Kill'

    def __init__(self):
        self._logger = logging.getLogger(__name__)

    @abstractmethod
    def receive_message(self):
        pass

    @abstractmethod
    def send_message(self, message: str):
        pass

    def check_whether_worker_is_ready(self):
        message = self.receive_message()
        if not message == self.MESSAGE_READY:
            raise CannotConnectToFuzzer()

    def send_ack(self):
        self.send_message(self.MESSAGE_ACK)

    def send_kill_signal(self):
        self._logger.info(f"Sending kill signal to worker")
        self.send_message(self._MESSAGE_KILL)
