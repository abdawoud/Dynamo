from typing import Dict

from src.content_provider_fuzzing.cp_api_models import UpdateApi
from src.content_provider_fuzzing.deencoders.apis.api_deencoder import ApiDeEncoder


class UpdateApiDeEncoder(ApiDeEncoder):
    __KEY_CONTENT_VALUES = 'contentValue'
    __KEY_SELECTION = 'selection'

    def _is_decodable(self, json_obj: Dict):
        return self.__KEY_CONTENT_VALUES in json_obj and \
               self.__KEY_SELECTION in json_obj

    def _try_to_decode(self, uri: str, json_obj: Dict):
        return UpdateApi(
            uri=uri,
            content_values=json_obj[self.__KEY_CONTENT_VALUES],
            selection=json_obj[self.__KEY_SELECTION]
        )

    def encode(self, o: UpdateApi):
        return {
            "type": self.get_request_type(),
            "uri": o.uri,
            "contentValue": o.content_values,
            "selection": o.selection
        }

    def get_request_type(self) -> str:
        return 'update_api_1'
