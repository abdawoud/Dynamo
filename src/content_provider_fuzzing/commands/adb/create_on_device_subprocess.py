from pathlib import Path
from typing import List

from src.content_provider_fuzzing.commands.adb.adb_command import AdbCommand
from src.content_provider_fuzzing.commands.create_subprocess_cmd import CreateSubprocessCmd


class CreateOnDeviceSubprocessCmd(CreateSubprocessCmd):
    def __init__(self, adb_path: Path, binary_path: str):
        adb_cmd_prefix: List[str] = AdbCommand.create_adb_cmd_prefix(adb_path)
        args = adb_cmd_prefix + ['shell', binary_path]
        super().__init__(args)
