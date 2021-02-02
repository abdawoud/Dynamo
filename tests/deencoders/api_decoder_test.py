import json

import pytest

from src.content_provider_fuzzing.cp_api_models import StaticAnalysisResult, CallApi, QueryApi, InsertApi, \
    UpdateApi, DeleteApi, ApiFuzzingResult
from src.content_provider_fuzzing.deencoders.apis.call_api_deencoder import CallApiDeEncoder
from src.content_provider_fuzzing.deencoders.deencoder import CannotDecodeException
from src.content_provider_fuzzing.deencoders.json_decoder import JsonDecoder
from tests.deencoders.api_encoder_test import json_string_from
from tests.deencoders.fuzz_test_input_generator import FuzzTestInputGenerator


def test_query_decoder(test_input_generator):
    json_string = test_input_generator.generate([
        {
            'type': 'query_api_1',
            'uri': test_input_generator.cp_uri,
            'projection': None,
            'selection': 'someSelection',
            'selectionArgs': None,
            'sortOrder': 'someOrder'
        }
    ])

    query_api = extract_api_class(json_string)
    assert isinstance(query_api, QueryApi)

    assert query_api.uri == test_input_generator.cp_uri
    assert query_api.projection is None
    assert query_api.selection == 'someSelection'
    assert query_api.selection_args is None
    assert query_api.sort_order == 'someOrder'


def test_call_decoder(test_input_generator):
    json_string = test_input_generator.generate([
        {
            "type": "call_api_11_29",
            "uri": test_input_generator.cp_uri,
            "apiLevel": "API_11",
            "method": "revoke_mediastore_uri_perms",
            "arg": None,
            "extras": None
        }
    ])

    call_api = extract_api_class(json_string)
    assert isinstance(call_api, CallApi)

    assert call_api.uri == test_input_generator.cp_uri
    assert call_api.api_level == 'API_11'
    assert call_api.method == 'revoke_mediastore_uri_perms'
    assert call_api.arg is None
    assert call_api.extras is None


def test_insert_decoder(test_input_generator):
    json_string = test_input_generator.generate([
        {
            "type": "insert_api_1",
            "uri": test_input_generator.cp_uri,
            "contentValue": {"type": "STRING", "key": "notificationpackage"},
        }
    ])

    insert_api = extract_api_class(json_string)
    assert isinstance(insert_api, InsertApi)

    assert insert_api.uri == test_input_generator.cp_uri
    assert insert_api.content_values == {"type": "STRING", "key": "notificationpackage"}


def test_update_decoder(test_input_generator):
    json_string = test_input_generator.generate([
        {
            "type": "update_api_1",
            "uri": test_input_generator.cp_uri,
            "contentValue": {"type": "STRING", "key": "_data"},
            "selection": None
        }
    ])

    update_api = extract_api_class(json_string)
    assert isinstance(update_api, UpdateApi)

    assert update_api.uri == test_input_generator.cp_uri
    assert update_api.content_values == {"type": "STRING", "key": "_data"}
    assert update_api.selection is None


def test_delete_decoder(test_input_generator):
    json_string = test_input_generator.generate([
        {
            "type": "delete_api_1",
            "uri": test_input_generator.cp_uri,
            "selection": None
        }
    ])

    delete_api = extract_api_class(json_string)
    assert isinstance(delete_api, DeleteApi)

    assert delete_api.uri == test_input_generator.cp_uri
    assert delete_api.selection is None


def test_fuzzing_result_decoder(test_input_generator):
    input_string = json_string_from({
        "input": {
            "type": "update_api_1",
            "uri": test_input_generator.cp_uri,
            "contentValue": {"type": "STRING", "key": "_data"},
            "selection": None
        },
        "permissions": ['read_permission', "write_permission"],
        "thrown_exception": 'SecurityException',
        "stacktrace": "This is a stacktrace."
    })

    actual = json.loads(input_string, cls=JsonDecoder)

    expected = ApiFuzzingResult(
        input=UpdateApi(
            uri=test_input_generator.cp_uri,
            content_values={"type": "STRING", "key": "_data"},
            selection=None
        ),
        permission_names=['read_permission', "write_permission"],
        thrown_exception='SecurityException',
        stacktrace="This is a stacktrace."
    )

    assert actual == expected


def test_api_decoder_on_json_without_key_type():
    decoder = CallApiDeEncoder()
    with pytest.raises(CannotDecodeException):
        decoder.try_to_decode({"Key": "Value"})


def extract_api_class(json_string: str):
    output: StaticAnalysisResult = json.loads(json_string, cls=JsonDecoder)
    return output.fuzzing_requests[0]


@pytest.fixture
def test_input_generator():
    cp_class_name = 'com.android.providers.downloads.DownloadProvider'
    authority = 'de.cispa.testcontentprovider.rw_protected_provider'
    cp_uri = f'content://{authority}/something/5'
    return FuzzTestInputGenerator(cp_class_name, cp_uri)
