
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit


@dataclass
class AndroidBundle:
    int_key_values: Dict[str, int]


@dataclass
class AndroidServiceMetadata:
    apk_path: Path
    package_name: str
    service_name: str
    bundle: AndroidBundle


class RunAndroidServiceUnit(ExecutionUnit):

    def __init__(self, adb_cmd_factory: AdbCmdFactory, service_metadata: AndroidServiceMetadata):
        self.adb_cmd_factory = adb_cmd_factory
        self.metadata = service_metadata

    def setup(self):
        apk_path = self.metadata.apk_path
        cmd = self.adb_cmd_factory.install(apk_path)
        cmd.execute()

    def run(self):
        start_service_cmd = self._build_start_service_cmd()
        cmd = self.adb_cmd_factory.shell(cmd=start_service_cmd)
        cmd.execute()

    def cleanup(self):
        package_name = self.metadata.package_name
        cmd = self.adb_cmd_factory.uninstall(package_name)
        cmd.execute()

    def _build_start_service_cmd(self):
        bundle_args_string = self._build_bundle_args_string()
        service_name = self.metadata.service_name
        return f'am start-foreground-service {bundle_args_string} ' \
               f'{service_name}'

    def _build_bundle_args_string(self):
        bundle_data = self.metadata.bundle.int_key_values
        bundle_args_string = ''
        for key, value in bundle_data.items():
            bundle_args_string += f' --ei {key} {value} '
        return bundle_args_string
