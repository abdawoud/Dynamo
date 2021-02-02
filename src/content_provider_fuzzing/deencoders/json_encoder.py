import json
from typing import Any

from src.content_provider_fuzzing.cp_api_models import QueryApi, CallApi, InsertApi, UpdateApi, DeleteApi, \
    StaticAnalysisResult, ApiFuzzingResult
from src.content_provider_fuzzing.deencoders.apis.call_api_deencoder import CallApiDeEncoder
from src.content_provider_fuzzing.deencoders.apis.delete_api_deencoder import DeleteApiDeEncoder
from src.content_provider_fuzzing.deencoders.apis.insert_api_deencoder import InsertApiDeEncoder
from src.content_provider_fuzzing.deencoders.apis.query_api_deencoder import QueryApiDeEncoder
from src.content_provider_fuzzing.deencoders.apis.update_api_deencoder import UpdateApiDeEncoder
from src.content_provider_fuzzing.deencoders.fuzzing_req_deencoder import FuzzReqForCpDeEncoder
from src.content_provider_fuzzing.deencoders.fuzzing_result_deencoder import FuzzingResultDeEncoder


class JsonEncoder(json.JSONEncoder):
    def __init__(self, *args, **kwargs) -> None:
        json.JSONEncoder.__init__(self, *args, **kwargs)
        self.type_to_encoder = self.__register_encoders()

    @staticmethod
    def __register_encoders():
        return {
            StaticAnalysisResult: FuzzReqForCpDeEncoder(),
            ApiFuzzingResult: FuzzingResultDeEncoder(),

            QueryApi: QueryApiDeEncoder(),
            CallApi: CallApiDeEncoder(),
            InsertApi: InsertApiDeEncoder(),
            UpdateApi: UpdateApiDeEncoder(),
            DeleteApi: DeleteApiDeEncoder()
        }

    def default(self, o: Any) -> Any:
        try:
            encoder = self.type_to_encoder[type(o)]
            return encoder.encode(o)
        except KeyError:
            return super().default(o)
