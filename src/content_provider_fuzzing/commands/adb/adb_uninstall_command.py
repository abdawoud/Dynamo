
from pathlib import Path

from src.content_provider_fuzzing.commands.adb.adb_command import AdbCommand


class AdbUninstallCommand(AdbCommand):

    def __init__(self, adb_path: Path, package_name: str, check_exit_code=True):
        args = ['uninstall', package_name]
        super().__init__(adb_path, args, check_exit_code)
