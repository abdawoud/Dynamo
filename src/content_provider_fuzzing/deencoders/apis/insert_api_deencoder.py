from typing import Dict

from src.content_provider_fuzzing.cp_api_models import InsertApi
from src.content_provider_fuzzing.deencoders.apis.api_deencoder import ApiDeEncoder


class InsertApiDeEncoder(ApiDeEncoder):
    __KEY_CONTENT_VALUES = 'contentValue'

    def _is_decodable(self, json_obj: Dict):
        return self.__KEY_CONTENT_VALUES in json_obj

    def _try_to_decode(self, uri: str, json_obj: Dict):
        return InsertApi(
            uri=uri,
            content_values=json_obj[self.__KEY_CONTENT_VALUES]
        )

    def encode(self, o: InsertApi):
        return {
            "type": self.get_request_type(),
            "uri": o.uri,
            "contentValue": o.content_values,
        }

    def get_request_type(self) -> str:
        return 'insert_api_1'
