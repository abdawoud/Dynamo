from typing import Dict

from src.content_provider_fuzzing.cp_api_models import QueryApi
from src.content_provider_fuzzing.deencoders.apis.api_deencoder import ApiDeEncoder


class QueryApiDeEncoder(ApiDeEncoder):
    __KEY_PROJECTION = 'projection'
    __KEY_SELECTION = 'selection'
    __KEY_SELECTION_ARGS = 'selectionArgs'
    __KEY_SORT_ORDER = 'sortOrder'

    def _is_decodable(self, json_obj: Dict):
        return self.__KEY_PROJECTION in json_obj and \
               self.__KEY_SELECTION in json_obj and \
               self.__KEY_SELECTION_ARGS in json_obj and \
               self.__KEY_SORT_ORDER in json_obj

    def _try_to_decode(self, uri: str, json_obj: Dict):
        return QueryApi(
            uri=uri,
            projection=json_obj[self.__KEY_PROJECTION],
            selection=json_obj[self.__KEY_SELECTION],
            selection_args=json_obj[self.__KEY_SELECTION_ARGS],
            sort_order=json_obj[self.__KEY_SORT_ORDER]
        )

    def encode(self, o: QueryApi):
        return {
            'type': self.get_request_type(),
            'uri': o.uri,
            'projection': o.projection,
            'selection': o.selection,
            'selectionArgs': o.selection_args,
            'sortOrder': o.sort_order
        }

    def get_request_type(self) -> str:
        return 'query_api_1'
