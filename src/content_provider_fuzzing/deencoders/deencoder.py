from abc import ABC, abstractmethod
from typing import Dict


class CannotDecodeException(Exception):
    pass


class DeEncoder(ABC):

    def try_to_decode(self, json_obj: Dict):
        if self._is_decodable(json_obj):
            return self.decode(json_obj)
        else:
            raise CannotDecodeException()

    @abstractmethod
    def _is_decodable(self, json_obj: Dict):
        pass

    @abstractmethod
    def decode(self, json_obj: Dict):
        pass

    @abstractmethod
    def encode(self, o):
        pass
