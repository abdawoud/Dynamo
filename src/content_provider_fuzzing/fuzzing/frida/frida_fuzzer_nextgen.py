import json
import logging
import queue
import subprocess
from dataclasses import dataclass
from multiprocessing import Queue
from pathlib import Path
from typing import List, Dict

import frida

from src.content_provider_fuzzing.deencoders.json_decoder import JsonDecoder
from src.content_provider_fuzzing.deencoders.json_encoder import JsonEncoder
from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit
from src.content_provider_fuzzing.execution_units.frida.frida_instrumentation_exec_unit import \
    FridaInstrumentationRequest, FridaInstrumentationExecUnit
from src.content_provider_fuzzing.fuzzing.frida.cp_to_process_mapper import CpClassToProcessMapper
from src.content_provider_fuzzing.fuzzing.fuzzer import FuzzingSessionResult
from src.content_provider_fuzzing.server_ipc.connection_to_fuzzer import ConnectionToFuzzer
from src.content_provider_fuzzing.cp_api_models import ApiFuzzingResult, StaticAnalysisResult, ContentProviderApi
from src.content_provider_fuzzing.execution_units.frida.frida_exec_unit import FridaExecUnit
from src.content_provider_fuzzing.fuzzing.fuzzing_unit import FuzzingUnit
from src.content_provider_fuzzing.fuzzing.permission_detection.enforcement_detector import EnforcementDetector
from src.content_provider_fuzzing.server_ipc.zeromq_server import ZeroMqServer
from utils import helpers


class FridaFuzzingUnit(FuzzingUnit):

    def get_child_units(self) -> List[ExecutionUnit]:
        child_units = super().get_child_units()
        fuzzer = child_units[-1]

        child_units[-1] = FridaExecUnit(self.adb_cmd_factory)
        child_units.append(fuzzer)

        return child_units


@dataclass
class FridaResult:
    stacktrace: str
    permission: str


class FridaFuzzerNextGen(ExecutionUnit):
    PACKAGE_NAME: str = 'saarland.cispa.contentproviderfuzzer'

    def __init__(self, static_analysis_results: List[StaticAnalysisResult],
                 unknown_permission: List[ApiFuzzingResult],
                 connection_to_fuzzer: ZeroMqServer):
        self.static_analysis_results = static_analysis_results
        self.unknown_permission = unknown_permission
        self.connection_to_fuzzer = connection_to_fuzzer

        self.process_name_to_fuzz_input = None
        self.cp_fuzzing_app_uid = None
        self.feedback_queue = Queue()

        self.logger = logging.getLogger(__name__)

    def setup(self):
        self.process_name_to_fuzz_input = self.__group_fuzz_inputs_by_process_name()
        self.cp_fuzzing_app_uid = self.get_app_uid()

    @staticmethod
    def get_app_uid(package_name=PACKAGE_NAME) -> str:
        adb_path = helpers.get_adb_path()
        completed_proc = subprocess.run([adb_path, '-e', 'shell', 'pm', 'list', 'packages', '-U', package_name],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        universal_newlines=True)
        # output format: 'package:saarland.cispa.contentproviderfuzzer uid:10096\n'
        return completed_proc.stdout.split(':')[-1].strip()

    def run(self):
        frida_device = frida.get_usb_device()
        frida_script = self._load_script()

        detected_permission_enforcement: List[ApiFuzzingResult] = []
        unknown_permission_enforcement: List[ApiFuzzingResult] = []

        for process_name, inputs in self.process_name_to_fuzz_input.items():
            self.connection_to_fuzzer.check_whether_worker_is_ready()
            serial_fuzz_job = {
                "batchRequests": False,
                "fuzzingRequests": []
            }
            serialized_job = json.dumps(serial_fuzz_job)
            self.connection_to_fuzzer.send_message(serialized_job)

            ack = self.connection_to_fuzzer.receive_message()
            assert ack == ConnectionToFuzzer.MESSAGE_ACK

            instrumentation_request = FridaInstrumentationRequest(
                frida_device=frida_device,
                target_process_name=process_name,
                frida_js_script=frida_script,
                on_message_function=self.__on_message
            )
            instrumentation_exec_unit = FridaInstrumentationExecUnit(instrumentation_request)
            instrumentation_exec_unit.setup()
            instrumentation_exec_unit.run()

            for fuzz_input in inputs:
                serialized = json.dumps(fuzz_input, cls=JsonEncoder)
                self.connection_to_fuzzer.send_message(serialized)

                message = self.connection_to_fuzzer.receive_message()

                try:
                    frida_feedback = self.feedback_queue.get(timeout=5)
                    frida_result: FridaResult = self.parse_message(frida_feedback)

                    api_result = ApiFuzzingResult(
                        input=fuzz_input,
                        permission_names=[frida_result.permission],
                        thrown_exception='',
                        stacktrace=frida_result.stacktrace
                    )
                    detected_permission_enforcement.append(api_result)
                except queue.Empty:
                    parsed_intermediate_result_message = json.loads(message, cls=JsonDecoder)
                    result = EnforcementDetector.extract_fuzzing_result(parsed_intermediate_result_message, [])
                    unknown_permission_enforcement.append(result)

            self.connection_to_fuzzer.send_ack()
            instrumentation_exec_unit.cleanup()

        return FuzzingSessionResult(
            detected_permissions=detected_permission_enforcement,
            unknown_permission=unknown_permission_enforcement
        )

    def _load_script(self):
        hook_script_path = Path(__file__).parent / 'cp_hook_api.js'
        with open(hook_script_path, 'r') as file:
            content = file.read()
            return content.replace('"<CP_FUZZER_UID>"', self.cp_fuzzing_app_uid)

    def __on_message(self, message, data):
        self.feedback_queue.put(message)

    def cleanup(self):
        pass

    def parse_message(self, message) -> FridaResult:
        try:
            payload = message['payload']
            data = payload.split(", ")
        except KeyError:
            self.logger.error(f'Frida Feedback: message: {message}, data: {data}')

        message_type = data[0]
        # DYNAMIC_ENFORCEMENT, permission, pid, uid, stacktrace
        if message_type == 'DYNAMIC_ENFORCEMENT':
            stacktrace = data[-1]
            for line in stacktrace.split('\n'):
                if '.query(' in line:
                    start_matcher = 'at '
                    start_index = line.find(start_matcher) + len(start_matcher)

                    end_matcher = '.query('
                    end_index = line.find(end_matcher)

                    result = FridaResult(permission=data[1], stacktrace=stacktrace)
                    return result

                if '.insert(' in line:
                    start_matcher = 'at '
                    start_index = line.find(start_matcher) + len(start_matcher)

                    end_matcher = '.insert('
                    end_index = line.find(end_matcher)

                    result = FridaResult(permission=data[1], stacktrace=stacktrace)
                    return result

                if '.update(' in line:
                    start_matcher = 'at '
                    start_index = line.find(start_matcher) + len(start_matcher)

                    end_matcher = '.update('
                    end_index = line.find(end_matcher)

                    class_name = line[start_index:end_index]
                    result = FridaResult(permission=data[1], stacktrace=stacktrace)
                    return result

                if '.delete(' in line:
                    start_matcher = 'at '
                    start_index = line.find(start_matcher) + len(start_matcher)

                    end_matcher = '.delete('
                    end_index = line.find(end_matcher)

                    class_name = line[start_index:end_index]
                    result = FridaResult(permission=data[1], stacktrace=stacktrace)
                    return result

                if '.call(' in line:
                    start_matcher = 'at '
                    start_index = line.find(start_matcher) + len(start_matcher)

                    end_matcher = '.call('
                    end_index = line.find(end_matcher)

                    class_name = line[start_index:end_index]
                    result = FridaResult(permission=data[1], stacktrace=stacktrace)
                    return result

            self.logger.error(f"Unknown case: {message}")

        self.logger.error("Unknown case in permission detection!")
        raise NotImplementedError()

    def __group_fuzz_inputs_by_process_name(self) -> Dict[str, ContentProviderApi]:
        class_name_to_fuzz_input = self.__group_fuzz_inputs_by_class_name()
        class_name_to_process_name = self.__create_class_name_to_process_name_dict()

        process_name_to_fuzz_input = {}
        for class_name, fuzz_input in class_name_to_fuzz_input.items():
            process_name = class_name_to_process_name[class_name]
            if process_name is None:
                continue

            inputs = process_name_to_fuzz_input.get(process_name, [])
            inputs += fuzz_input
            process_name_to_fuzz_input[process_name] = inputs

        return process_name_to_fuzz_input

    def __create_class_name_to_process_name_dict(self) -> Dict[str, str]:
        class_name_to_fuzz_input = self.__group_fuzz_inputs_by_class_name()

        cp_class_to_process_name_mapper = CpClassToProcessMapper()
        cp_class_to_process_name_mapper.create_mapping()

        class_name_to_process_name = {}
        for cp_class_name in class_name_to_fuzz_input.keys():
            process_name = cp_class_to_process_name_mapper.get_process_name_for_cp_class_name(cp_class_name)
            class_name_to_process_name[cp_class_name] = process_name

        return class_name_to_process_name

    def __group_fuzz_inputs_by_class_name(self) -> Dict[str, ContentProviderApi]:
        class_name_to_fuzz_input = {}
        for api in self.unknown_permission:
            fuzz_input = api.input

            for static_result in self.static_analysis_results:
                if fuzz_input in static_result.fuzzing_requests:
                    class_name = static_result.class_name

                    inputs = class_name_to_fuzz_input.get(class_name, [])
                    inputs.append(fuzz_input)

                    class_name_to_fuzz_input[class_name] = inputs

        return class_name_to_fuzz_input
