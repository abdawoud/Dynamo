from typing import Dict

from src.content_provider_fuzzing.cp_api_models import StaticAnalysisResult
from src.content_provider_fuzzing.deencoders.deencoder import DeEncoder


class FuzzReqForCpDeEncoder(DeEncoder):
    __KEY_CLASS_NAME = 'className'
    __KEY_FUZZING_REQUESTS = 'data'

    def _is_decodable(self, json_obj: Dict):
        return self.__KEY_CLASS_NAME in json_obj and \
               self.__KEY_FUZZING_REQUESTS in json_obj

    def decode(self, json_obj: Dict):
        return StaticAnalysisResult(
            class_name=json_obj[self.__KEY_CLASS_NAME],
            fuzzing_requests=json_obj[self.__KEY_FUZZING_REQUESTS]
        )

    def encode(self, o: StaticAnalysisResult):
        return {
            self.__KEY_CLASS_NAME: o.class_name,
            self.__KEY_FUZZING_REQUESTS: o.fuzzing_requests
        }
