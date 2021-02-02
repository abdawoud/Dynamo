import json
import logging
import subprocess
from dataclasses import dataclass
from typing import List, Union

from utils import helpers


@dataclass
class ContentProviderRecord:
    class_name: str
    package_name: str
    process_name: str


class CpClassToProcessMapper:

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.cp_class_to_cp_record = None

    def create_mapping(self):
        self.logger.info("Running dumpsys in emulator.")
        dumpsys_content = self.__run_dumpsys_in_emu()

        self.logger.info("Creating content provider to process mapping.")
        self.cp_class_to_cp_record = self.__create_cp_class_to_record_mapping(dumpsys_content)

        self.extract_from_per_package_stats(dumpsys_content)

    def get_process_name_for_cp_class_name(self, class_name: str) -> Union[str, None]:
        try:
            cp_record = self.cp_class_to_cp_record[class_name]
            return cp_record.process_name
        except KeyError:
            self.logger.error(f"Cannot map {class_name} to process.")
            return None

    def __create_cp_class_to_record_mapping(self, dumpsys_content: List[str]):
        cp_class_to_cp_record = {}

        process_line = False
        last_cp_class_name = None
        for line in dumpsys_content:
            if 'Published single-user content providers (by class):' in line:
                process_line = True

            if process_line:
                if 'Single-user authority to provider mappings:' in line:
                    process_line = False

                if process_line:
                    # * ContentProviderRecord{89e3e94 u0 com.android/com.android.car.ui.core.CarUiInstaller}
                    if 'ContentProviderRecord{' in line:
                        last_cp_class_name = self.__extract_cp_class_name(line)

                    package_name = self.__extract_pkg_name(line)
                    process_name = self.__extract_process_name(line)

                    if package_name is not None and process_name is not None:
                        cp_record = ContentProviderRecord(class_name=last_cp_class_name,
                                                          package_name=package_name,
                                                          process_name=process_name)
                        cp_class_to_cp_record[last_cp_class_name] = cp_record

        return cp_class_to_cp_record

    @staticmethod
    def __parse_app_input(path: str):
        with open(path, 'r') as f:
            return json.load(f)

    @staticmethod
    def __run_dumpsys_in_emu() -> List[str]:
        adb_path = helpers.get_adb_path()
        completed_proc = subprocess.run([adb_path, '-e', 'shell', 'dumpsys'],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        universal_newlines=True)
        return completed_proc.stdout.split('\n')

    @staticmethod
    def __extract_cp_class_name(line: str):
        # * ContentProviderRecord{89e3e94 u0 com.android/com.android.car.ui.core.CarUiInstaller}\n
        records = line.split(' ')
        cp_class_name = records[-1].strip()[:-1]  # last item & remove '}\n'

        # com.android.telephony/.TelephonyProvider -> com.android.telephony.TelephonyProvider
        result = cp_class_name.replace('/.', '.')

        # com.android.inputmethod.latin/com.android.inputmethod.dictionarypack.DictionaryProvider
        # -> com.android.inputmethod.dictionarypack.DictionaryProvider
        if '/' in result and 'androidx' not in result:
            result = result.split('/')[1]
        return result

    @staticmethod
    def __extract_pkg_name(line: str):
        # package=com.android.bluetooth process=com.android.bluetooth
        package_matcher = 'package='
        if package_matcher in line:
            start_index = line.find(package_matcher) + len(package_matcher)
            return line[start_index:].split(' ')[0]
        return None

    @staticmethod
    def __extract_process_name(line: str):
        process_matcher = 'process='
        if process_matcher in line:
            start_index = line.find(process_matcher) + len(process_matcher)
            return line[start_index:].strip()
        return None

    def extract_from_per_package_stats(self, dumpsys_content: List[str]):
        process_lines = False
        need_next_line = False

        last_cp_class_name = None
        for line in dumpsys_content:
            line = line.strip()

            if line == 'Per-Package Stats:':
                process_lines = True

            if line == 'Multi-Package Common Processes:':
                process_lines = False

            if process_lines:
                if need_next_line:

                    if last_cp_class_name not in self.cp_class_to_cp_record:
                        # 'Process: android.process.acore'
                        process_name = line.split(' ')[1]

                        cp_record = ContentProviderRecord(class_name=last_cp_class_name,
                                                          package_name='',
                                                          process_name=process_name)
                        self.cp_class_to_cp_record[last_cp_class_name] = cp_record
                        need_next_line = False

                if 'Association' in line:
                    need_next_line = True

                    # 'Association com.android.providers.telephony.SmsProvider:'
                    cp_class_name = line.split(' ')[1].replace(':', '')
                    last_cp_class_name = cp_class_name
