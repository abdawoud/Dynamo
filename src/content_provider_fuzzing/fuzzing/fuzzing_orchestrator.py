import json
from pathlib import Path

from src.content_provider_fuzzing.deencoders.json_decoder import JsonDecoder
from src.content_provider_fuzzing.fuzzing.batch_fuzzer import BatchFuzzer
from src.content_provider_fuzzing.fuzzing.fuzzer import FuzzingSessionResult
from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.fuzzing.frida.frida_fuzzer_nextgen import FridaFuzzingUnit, FridaFuzzerNextGen
from src.content_provider_fuzzing.fuzzing.fuzzing_unit import FuzzingUnit
from src.content_provider_fuzzing.fuzzing.result_writer import ResultWriter
from src.content_provider_fuzzing.server_ipc.zeromq_server import ZeroMqServer


class FuzzingOrchestrator:
    def __init__(self, adb_cmd_factory: AdbCmdFactory, fuzzer_apk_path: Path, static_analysis_output_path):
        self.adb_cmd_factory = adb_cmd_factory
        self.fuzzer_apk_path = fuzzer_apk_path
        self.static_analysis_output_path = static_analysis_output_path

        self.result_writer = ResultWriter('dynamo_results.json')
        self.unknown_result_writer = ResultWriter('unknown_permission_enforcements.json')

    def run(self):
        with open(self.static_analysis_output_path, 'r') as f:
            fuzz_input = json.load(f, cls=JsonDecoder)

        fuzz_connection = ZeroMqServer()
        fuzzer = BatchFuzzer(fuzz_input, fuzz_connection)

        fuzz_unit = FuzzingUnit(
            self.adb_cmd_factory,
            self.fuzzer_apk_path,
            fuzz_connection,
            fuzzer
        )

        fuzz_unit.setup()
        results: FuzzingSessionResult = fuzz_unit.run()
        fuzz_unit.cleanup()

        fuzzer = FridaFuzzerNextGen(
            static_analysis_results=fuzz_input,
            unknown_permission=results.unknown_permission,
            connection_to_fuzzer=fuzz_connection
        )
        fuzz_unit = FridaFuzzingUnit(
            self.adb_cmd_factory,
            self.fuzzer_apk_path,
            fuzz_connection,
            fuzzer
        )

        fuzz_unit.setup()
        frida_results: FuzzingSessionResult = fuzz_unit.run()
        fuzz_unit.cleanup()

        # Combine results
        detected_all = results.detected_permissions + frida_results.detected_permissions
        unknown_all = frida_results.unknown_permission

        self.result_writer.write(detected_all)
        self.unknown_result_writer.write(unknown_all)

        return results
