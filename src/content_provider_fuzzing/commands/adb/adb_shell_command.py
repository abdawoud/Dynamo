
from pathlib import Path

from src.content_provider_fuzzing.commands.adb.adb_command import AdbCommand


class AdbShellCommand(AdbCommand):

    def __init__(self, adb_path: Path, cmd: str, check_exit_code=False):
        args = ['shell', cmd]
        super().__init__(adb_path, args, check_exit_code)
