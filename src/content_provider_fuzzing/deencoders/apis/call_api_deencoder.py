from typing import Dict

from src.content_provider_fuzzing.cp_api_models import CallApi
from src.content_provider_fuzzing.deencoders.apis.api_deencoder import ApiDeEncoder


class CallApiDeEncoder(ApiDeEncoder):
    __KEY_API_LEVEL = 'apiLevel'
    __KEY_METHOD = 'method'
    __KEY_ARG = 'arg'
    __KEY_EXTRAS = 'extras'

    def _is_decodable(self, json_obj: Dict):
        return self.__KEY_API_LEVEL in json_obj and \
               self.__KEY_METHOD in json_obj and \
               self.__KEY_ARG in json_obj and \
               self.__KEY_EXTRAS in json_obj

    def _try_to_decode(self, uri: str, json_obj: Dict):
        return CallApi(
            uri=uri,
            api_level=json_obj[self.__KEY_API_LEVEL],
            method=json_obj[self.__KEY_METHOD],
            arg=json_obj[self.__KEY_ARG],
            extras=json_obj[self.__KEY_EXTRAS],
        )

    def encode(self, o: CallApi):
        return {
            "type": self.get_request_type(),
            "uri": o.uri,
            "apiLevel": o.api_level,
            "method": o.method,
            "arg": o.arg,
            "extras": o.extras
        }

    def get_request_type(self) -> str:
        return 'call_api_11_29'
