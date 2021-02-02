import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict

import pytest

from src.content_provider_fuzzing.deencoders.json_decoder import JsonDecoder
from src.content_provider_fuzzing.fuzzing.fuzzer import Fuzzer, FuzzingSessionResult
from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.cp_api_models import ApiFuzzingResult
from src.content_provider_fuzzing.fuzzing.fuzzing_unit import FuzzingUnit
from src.content_provider_fuzzing.fuzzing.permission_detection.enforcement_detector import EnforcementDetector
from src.content_provider_fuzzing.server_ipc.zeromq_server import ZeroMqServer


class SampleProviderTest(ABC):
    FUZZER_APK_PATH = '/home/user/Documents/ContentProviderFuzzer/app/build/outputs/apk/debug/app-debug.apk'

    @abstractmethod
    def get_enforcement_detector(self) -> EnforcementDetector:
        pass

    @abstractmethod
    def expected_output_file_name(self) -> str:
        pass

    @pytest.fixture(autouse=True)
    def setup_and_teardown(self, adb_cmd_factory: AdbCmdFactory):
        self.adb_cmd_factory = adb_cmd_factory

    @pytest.fixture
    def fuzz_connection(self):
        return ZeroMqServer()

    def _run_fuzzer(self, fuzzer: Fuzzer, fuzz_connection) -> FuzzingSessionResult:
        fuzz_unit = FuzzingUnit(self.adb_cmd_factory, Path(self.FUZZER_APK_PATH), fuzz_connection, fuzzer)

        fuzz_unit.setup()
        results: FuzzingSessionResult = fuzz_unit.run()
        fuzz_unit.cleanup()

        return results

    def _assert_fuzzing_results(self, results: FuzzingSessionResult, expected_output: Dict):
        # detected
        detected_expected_output = expected_output['detected_permissions']
        actual = results.detected_permissions
        self.__assert_api_fuzzing_result(actual_list=actual, expected_list=detected_expected_output)

        # unknown
        detected_expected_output = expected_output['unknown_permissions']
        actual = results.unknown_permission
        self.__assert_api_fuzzing_result(actual_list=actual, expected_list=detected_expected_output)

    def __assert_api_fuzzing_result(self, actual_list: List[ApiFuzzingResult], expected_list: [ApiFuzzingResult]):
        assert len(actual_list) == len(expected_list)

        for i in range(len(actual_list)):
            actual = actual_list[i]
            expected = expected_list[i]

            self._assert_permission_name_in_result(
                actual=actual.permission_names, expected=expected.permission_names
            )

            enforcement_detector = self.get_enforcement_detector()
            assert enforcement_detector.is_enforcement(actual.thrown_exception)
            assert enforcement_detector.is_enforcement(actual.stacktrace)

    @staticmethod
    def _assert_permission_name_in_result(actual, expected):
        assert len(set(actual).intersection(set(expected))) == 1

    def _get_expected_output(self):
        expected_output_file = Path(
            __file__).parent / 'expected_output_files' / self.expected_output_file_name()

        with open(expected_output_file, 'r') as f:
            return json.load(f, cls=JsonDecoder)
