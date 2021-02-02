from abc import ABC, abstractmethod
from typing import Dict, Union

from src.content_provider_fuzzing.deencoders.deencoder import DeEncoder, CannotDecodeException


class ApiDeEncoder(DeEncoder, ABC):
    __KEY_TYPE = 'type'
    __KEY_URI = 'uri'

    def try_to_decode(self, json_obj: Dict):
        try:
            req_type = json_obj[self.__KEY_TYPE]
            if req_type == self.get_request_type() and self._is_decodable(json_obj):
                uri = json_obj[self.__KEY_URI]
                return self._try_to_decode(uri, json_obj)

        except KeyError:
            pass

        raise CannotDecodeException()

    def decode(self, json_obj: Dict):
        pass

    @abstractmethod
    def _try_to_decode(self, uri: str, json_obj: Dict):
        pass

    @abstractmethod
    def get_request_type(self) -> Union[str, None]:
        pass
