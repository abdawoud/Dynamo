from typing import Dict

from src.content_provider_fuzzing.cp_api_models import DeleteApi
from src.content_provider_fuzzing.deencoders.apis.api_deencoder import ApiDeEncoder


class DeleteApiDeEncoder(ApiDeEncoder):
    __KEY_SELECTION = 'selection'

    def _is_decodable(self, json_obj: Dict):
        return self.__KEY_SELECTION in json_obj

    def _try_to_decode(self, uri: str, json_obj: Dict):
        return DeleteApi(
            uri=uri,
            selection=json_obj[self.__KEY_SELECTION]
        )

    def encode(self, o: DeleteApi):
        return {
            "type": self.get_request_type(),
            "uri": o.uri,
            "selection": o.selection
        }

    def get_request_type(self) -> str:
        return 'delete_api_1'
