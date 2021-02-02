
from pathlib import Path

from src.content_provider_fuzzing.commands.adb.adb_command import AdbCommand


class AdbInstallCommand(AdbCommand):

    def __init__(self, adb_path: Path, apk_path: Path, check_exit_code=True):
        args = ['install', apk_path.as_posix()]
        super().__init__(adb_path, args, check_exit_code)
