from src.content_provider_fuzzing.fuzzing.batch_fuzzer import BatchFuzzer
from src.content_provider_fuzzing.fuzzing.fuzzer import FuzzingSessionResult
from src.content_provider_fuzzing.cp_api_models import StaticAnalysisResult
from src.content_provider_fuzzing.fuzzing.permission_detection.enforcement_detector import EnforcementDetector
from src.content_provider_fuzzing.fuzzing.permission_detection.read_enforcement_detector import ReadEnforcementDetector
from tests.sample_provider_tests.sample_provider_test import SampleProviderTest


class TestReadProtectedProvider(SampleProviderTest):

    def test_read_manifest_enforcement(self, fuzz_connection):
        expected_output = self._get_expected_output()
        fuzzing_input = expected_output['detected_permissions'] + expected_output['unknown_permissions']
        fuzzing_requests = list(map(lambda item: item.input, fuzzing_input))

        fuzz_input = [
            StaticAnalysisResult(
                class_name='someClass',
                fuzzing_requests=fuzzing_requests
            )
        ]

        fuzzer = BatchFuzzer(fuzz_input, fuzz_connection)
        results: FuzzingSessionResult = self._run_fuzzer(fuzzer, fuzz_connection)
        self._assert_fuzzing_results(results, expected_output)

    def get_enforcement_detector(self) -> EnforcementDetector:
        return ReadEnforcementDetector()

    def expected_output_file_name(self) -> str:
        return 'expected_output_test_read_manifest_enforcement.json'
