from typing import Dict

from src.content_provider_fuzzing.cp_api_models import ApiFuzzingResult
from src.content_provider_fuzzing.deencoders.deencoder import DeEncoder


class FuzzingResultDeEncoder(DeEncoder):
    __KEY_INPUT = 'input'
    __KEY_PERMISSIONS = 'permissions'
    __KEY_THROWN_EXCEPTION = 'thrown_exception'
    __KEY_STACKTRACE = 'stacktrace'

    def _is_decodable(self, json_obj: Dict):
        return self.__KEY_INPUT in json_obj and \
               self.__KEY_PERMISSIONS in json_obj and \
               self.__KEY_THROWN_EXCEPTION in json_obj and \
               self.__KEY_STACKTRACE in json_obj

    def decode(self, json_obj: Dict):
        return ApiFuzzingResult(
            input=json_obj[self.__KEY_INPUT],
            permission_names=json_obj[self.__KEY_PERMISSIONS],
            thrown_exception=json_obj[self.__KEY_THROWN_EXCEPTION],
            stacktrace=json_obj[self.__KEY_STACKTRACE]
        )

    def encode(self, o: ApiFuzzingResult):
        return {
            self.__KEY_INPUT: o.input,
            self.__KEY_PERMISSIONS: o.permission_names,
            self.__KEY_THROWN_EXCEPTION: o.thrown_exception,
            self.__KEY_STACKTRACE: o.stacktrace
        }
