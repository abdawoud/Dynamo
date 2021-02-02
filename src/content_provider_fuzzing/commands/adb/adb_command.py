from pathlib import Path
from typing import List

from src.content_provider_fuzzing.commands.exec_command import ExecCommand


class AdbCommand(ExecCommand):
    CF_IP_AND_PORT = '127.0.0.1:6520'

    def __init__(self, adb_path: Path, args: List[str], check_exit_code=True):
        super().__init__(args, check_exit_code)
        self.adb_path = adb_path

    def execute(self) -> List[str]:
        prefix = self.create_adb_cmd_prefix(self.adb_path)
        self.args = prefix + self.args
        return super().execute()

    @staticmethod
    def create_adb_cmd_prefix(adb_path: Path):
        return [
            adb_path,
            '-e',  # -e: use TCP/IP device (error if multiple TCP/IP devices available)
            '-s', AdbCommand.CF_IP_AND_PORT  # -s SERIAL:  use device with given serial (overrides $ANDROID_SERIAL)
        ]
