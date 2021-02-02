import json
from typing import Dict

import pytest

from src.content_provider_fuzzing.cp_api_models import QueryApi, CallApi, InsertApi, UpdateApi, DeleteApi, \
    ApiFuzzingResult
from src.content_provider_fuzzing.deencoders.json_encoder import JsonEncoder


def test_query_encoder(uri):
    query_api = QueryApi(
        uri=uri,
        projection=None,
        selection='someSelection',
        selection_args=None,
        sort_order='someOrder'
    )

    expected = json_string_from({
        'type': 'query_api_1',
        'uri': uri,
        'projection': None,
        'selection': 'someSelection',
        'selectionArgs': None,
        'sortOrder': 'someOrder'
    })

    assert parse_api_input(query_api) == expected


def test_call_encoder(uri):
    call_api = CallApi(
        uri=uri,
        api_level="API_11",
        method="revoke_mediastore_uri_perms",
        arg=None,
        extras=None
    )

    expected = json_string_from({
        "type": "call_api_11_29",
        "uri": uri,
        "apiLevel": "API_11",
        "method": "revoke_mediastore_uri_perms",
        "arg": None,
        "extras": None
    })

    assert parse_api_input(call_api) == expected


def test_insert_encoder(uri):
    insert_api = InsertApi(
        uri=uri,
        content_values={"type": "STRING", "key": "notificationpackage"}
    )

    expected = json_string_from({
        "type": "insert_api_1",
        "uri": uri,
        "contentValue": {"type": "STRING", "key": "notificationpackage"},
    })

    assert parse_api_input(insert_api) == expected


def test_update_encoder(uri):
    update_api = UpdateApi(
        uri=uri,
        content_values={"type": "STRING", "key": "_data"},
        selection=None
    )

    expected = json_string_from({
        "type": "update_api_1",
        "uri": uri,
        "contentValue": {"type": "STRING", "key": "_data"},
        "selection": None
    })

    assert parse_api_input(update_api) == expected


def test_delete_encoder(uri):
    delete_api = DeleteApi(
        uri=uri,
        selection=None
    )

    expected = json_string_from({
        "type": "delete_api_1",
        "uri": uri,
        "selection": None
    })

    assert parse_api_input(delete_api) == expected


def test_fuzzing_result_encoder(uri):
    fuzzing_result = ApiFuzzingResult(
        input=UpdateApi(
            uri=uri,
            content_values={"type": "STRING", "key": "_data"},
            selection=None
        ),
        permission_names=['read_permission', "write_permission"],
        thrown_exception='SecurityException',
        stacktrace="This is a stacktrace."
    )

    expected = json_string_from({
        "input": {
            "type": "update_api_1",
            "uri": uri,
            "contentValue": {"type": "STRING", "key": "_data"},
            "selection": None
        },
        "permissions": ['read_permission', "write_permission"],
        "thrown_exception": 'SecurityException',
        "stacktrace": "This is a stacktrace."
    })

    assert parse_api_input(fuzzing_result) == expected


def json_string_from(obj: Dict) -> str:
    return json.dumps(obj)


def parse_api_input(api) -> str:
    return json.dumps(api, cls=JsonEncoder)


@pytest.fixture
def uri():
    authority = 'de.cispa.testcontentprovider.rw_protected_provider'
    return f'content://{authority}/something/5'
