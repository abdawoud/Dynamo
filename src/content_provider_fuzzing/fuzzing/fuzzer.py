import json
from abc import abstractmethod
from dataclasses import dataclass
from typing import Dict, List

from src.content_provider_fuzzing.cp_api_models import StaticAnalysisResult, ApiFuzzingResult
from src.content_provider_fuzzing.deencoders.json_encoder import JsonEncoder
from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit
from src.content_provider_fuzzing.fuzzing.permission_detection.enforcement_detector import EnforcementDetector
from src.content_provider_fuzzing.fuzzing.permission_detection.private_enforcement_detector import \
    PrivateEnforcementDetector
from src.content_provider_fuzzing.fuzzing.permission_detection.read_enforcement_detector import ReadEnforcementDetector
from src.content_provider_fuzzing.fuzzing.permission_detection.rw_enforcement_detector import RwEnforcementDetector
from src.content_provider_fuzzing.fuzzing.permission_detection.write_enforcement_detector import \
    WriteEnforcementDetector
from src.content_provider_fuzzing.server_ipc.zeromq_server import ZeroMqServer


@dataclass
class FuzzingSessionResult:
    detected_permissions: List[ApiFuzzingResult]
    unknown_permission: List[ApiFuzzingResult]


class Fuzzer(ExecutionUnit):
    def __init__(self, results_of_static_analysis: List[StaticAnalysisResult],
                 connection_to_fuzzer: ZeroMqServer):
        self.results_of_static_analysis = results_of_static_analysis
        self.connection_to_fuzzer = connection_to_fuzzer

        self.detected_permission_enforcement: List[ApiFuzzingResult] = []
        self.unknown_permission_enforcement: List[ApiFuzzingResult] = []

        self.permission_detectors = [
            RwEnforcementDetector(),
            ReadEnforcementDetector(),
            WriteEnforcementDetector(),
            PrivateEnforcementDetector()
        ]

    def setup(self):
        pass

    def run(self) -> FuzzingSessionResult:
        self.detected_permission_enforcement.clear()
        self.unknown_permission_enforcement.clear()

        self.connection_to_fuzzer.check_whether_worker_is_ready()

        job = self.__create_fuzzing_job()
        data_to_send = self._serialize(job)

        # send data to fuzz!
        self.connection_to_fuzzer.send_message(data_to_send)

        self._fuzz(job)

        return FuzzingSessionResult(
            detected_permissions=self.detected_permission_enforcement,
            unknown_permission=self.unknown_permission_enforcement
        )

    def cleanup(self):
        self.connection_to_fuzzer.send_kill_signal()

    def _process_fuzz_result(self, parsed_result_message: Dict):
        thrown_exception = parsed_result_message['thrownException']
        if thrown_exception is None:
            return

        for manifest_enforcement_detector in self.permission_detectors:
            if manifest_enforcement_detector.is_enforcement(thrown_exception):
                r = manifest_enforcement_detector.extract_fuzzing_result_with_permissions(parsed_result_message)
                self.detected_permission_enforcement.append(r)
                return

        if EnforcementDetector.is_security_exception(thrown_exception):
            r = self.permission_detectors[0].extract_fuzzing_result_no_permissions(parsed_result_message)
            self.unknown_permission_enforcement.append(r)

    @abstractmethod
    def _fuzz(self, fuzzing_job: Dict) -> None:
        pass

    def __create_fuzzing_job(self):
        from src.content_provider_fuzzing.fuzzing.batch_fuzzer import BatchFuzzer
        is_batch_mode = type(self) == BatchFuzzer

        return {
            "batchRequests": is_batch_mode,
            "fuzzingRequests": self.__create_fuzzing_requests_from_fuzzing_input()
        }

    def __create_fuzzing_requests_from_fuzzing_input(self):
        fuzzing_requests = []
        for static_analysis_result in self.results_of_static_analysis:
            fuzzing_requests += static_analysis_result.fuzzing_requests
        return fuzzing_requests

    @staticmethod
    def _serialize(fuzzing_job) -> str:
        return json.dumps(fuzzing_job, cls=JsonEncoder)
