from pathlib import Path
from time import sleep
from typing import List

from src.content_provider_fuzzing.commands.adb.adb_command import AdbCommand
from src.content_provider_fuzzing.commands.adb.adb_wait_for_device_command import AdbWaitForDeviceCommand


class AdbRootCommand(AdbCommand):

    def __init__(self, adb_path: Path, check_exit_code=True):
        args = ['root']
        super().__init__(adb_path, args, check_exit_code)

    def execute(self) -> List[str]:
        output = super().execute()

        sleep(1)
        wait_cmd = AdbWaitForDeviceCommand(self.adb_path)
        wait_cmd.execute()

        return output
