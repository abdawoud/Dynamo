import json
import time
from pathlib import Path
from typing import Dict

from src.content_provider_fuzzing.emulator.cuttlefish import Cuttlefish
from src.content_provider_fuzzing.logging_setup import setup_logging
from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.fuzzing.fuzzing_orchestrator import FuzzingOrchestrator
from utils.helpers import get_specific_out_dir


class CpFuzzingMain:
    CONFIG_CF_DIR = 'cf_dir'
    CONFIG_FUZZER_APK = 'fuzzer_apk_path'
    CONFIG_STATIC_ANALYSIS_OUTPUT = 'static_analysis_output_path'

    def __init__(self, main_script_path: str):
        self.config_dir = Path(main_script_path).parent
        self.config = None

    def main(self):
        self.__setup_logging()
        self.config = self.__parse_config()

        cf = Cuttlefish(
            cf_dir=self.__get_cf_dir(),
            reuse_instance=True
        )
        started_by_dynamo = cf.start()
        if started_by_dynamo:
            cf.wait_until_ready()

        orchestrator = FuzzingOrchestrator(
            adb_cmd_factory=self.__create_adb_cmd_factory(),
            fuzzer_apk_path=self.__get_fuzzer_apk(),
            static_analysis_output_path=self.__get_static_analysis_output()
        )
        orchestrator.run()

        if started_by_dynamo:
            cf.stop()

    def __setup_logging(self):
        cp_fuzzing_results_dir_path = Path(get_specific_out_dir('cp_fuzzing_results'))
        self.results_dir = cp_fuzzing_results_dir_path / time.strftime("%Y_%m_%d_%H_%M_%S", time.gmtime())
        self.results_dir.mkdir(parents=True)

        path = self.results_dir / "dynamo_log.txt"
        setup_logging(log_file_path=path)

    def __parse_config(self) -> Dict:
        config_file_path = self.config_dir / 'cp_fuzz_config.json'
        with open(config_file_path, 'r') as f:
            return json.load(f)

    def __create_adb_cmd_factory(self):
        cf_dir = self.__get_cf_dir()
        android_sdk_path = Path(cf_dir)

        adb_path = android_sdk_path / 'bin' / 'adb'
        return AdbCmdFactory(adb_path)

    def __get_cf_dir(self):
        return Path(self.config[self.CONFIG_CF_DIR])

    def __get_fuzzer_apk(self):
        return Path(self.config[self.CONFIG_FUZZER_APK])

    def __get_static_analysis_output(self):
        return Path(self.config[self.CONFIG_STATIC_ANALYSIS_OUTPUT])
