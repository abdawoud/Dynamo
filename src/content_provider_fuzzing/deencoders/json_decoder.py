import json
from typing import Dict

from src.content_provider_fuzzing.deencoders.apis.call_api_deencoder import CallApiDeEncoder
from src.content_provider_fuzzing.deencoders.apis.delete_api_deencoder import DeleteApiDeEncoder
from src.content_provider_fuzzing.deencoders.apis.insert_api_deencoder import InsertApiDeEncoder
from src.content_provider_fuzzing.deencoders.apis.query_api_deencoder import QueryApiDeEncoder
from src.content_provider_fuzzing.deencoders.apis.update_api_deencoder import UpdateApiDeEncoder
from src.content_provider_fuzzing.deencoders.deencoder import CannotDecodeException
from src.content_provider_fuzzing.deencoders.fuzzing_req_deencoder import FuzzReqForCpDeEncoder
from src.content_provider_fuzzing.deencoders.fuzzing_result_deencoder import FuzzingResultDeEncoder


class JsonDecoder(json.JSONDecoder):
    __KEY_TYPE = 'type'
    __KEY_CLASS_NAME = 'className'
    __KEY_URI = 'uri'
    __KEY_DATA = 'data'

    def __init__(self, *args, **kwargs) -> None:
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)
        self.decoders = self.__register_decoders()

    def object_hook(self, obj: Dict):
        try:
            return self.__decode(obj)
        except NotImplementedError:
            return obj

    @staticmethod
    def __register_decoders():
        return [
            FuzzReqForCpDeEncoder(),
            FuzzingResultDeEncoder(),

            CallApiDeEncoder(),
            DeleteApiDeEncoder(),
            InsertApiDeEncoder(),
            QueryApiDeEncoder(),
            UpdateApiDeEncoder(),
        ]

    def __decode(self, obj: Dict):
        for s in self.decoders:
            try:
                return s.try_to_decode(obj)
            except CannotDecodeException:
                pass

        raise NotImplementedError()
