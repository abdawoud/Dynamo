from pathlib import Path
from typing import List

from src.content_provider_fuzzing.commands.adb.adb_command import AdbCommand
from src.content_provider_fuzzing.commands.adb.adb_install_command import AdbInstallCommand
from src.content_provider_fuzzing.commands.adb.adb_root_command import AdbRootCommand
from src.content_provider_fuzzing.commands.adb.adb_shell_command import AdbShellCommand
from src.content_provider_fuzzing.commands.adb.adb_uninstall_command import AdbUninstallCommand
from src.content_provider_fuzzing.commands.adb.adb_unroot_command import AdbUnrootCommand
from src.content_provider_fuzzing.commands.adb.create_on_device_subprocess import CreateOnDeviceSubprocessCmd
from src.content_provider_fuzzing.commands.adb.setup_adb_reverse_port_forwarding_cmd import \
    SetupAdbReversePortForwardingCmd


class AdbCmdFactory:
    def __init__(self, adb_path: Path):
        self._adb_path = adb_path

    def adb(self, args: List[str], check_exit_code: bool):
        return AdbCommand(adb_path=self._adb_path, args=args, check_exit_code=check_exit_code)

    def shell(self, cmd: str, check_exit_code=False):
        return AdbShellCommand(adb_path=self._adb_path, cmd=cmd, check_exit_code=check_exit_code)

    def install(self, apk_path: Path, check_exit_code=True):
        return AdbInstallCommand(adb_path=self._adb_path, apk_path=apk_path, check_exit_code=check_exit_code)

    def uninstall(self, package_name: str, check_exit_code=True):
        return AdbUninstallCommand(adb_path=self._adb_path, package_name=package_name, check_exit_code=check_exit_code)

    def root(self):
        return AdbRootCommand(self._adb_path)

    def unroot(self):
        return AdbUnrootCommand(self._adb_path)

    def create_on_device_subprocess(self, binary_path: str):
        return CreateOnDeviceSubprocessCmd(adb_path=self._adb_path, binary_path=binary_path)

    def setup_reverse_port_forwarding(self, host_port: int, device_port: int):
        return SetupAdbReversePortForwardingCmd(adb_path=self._adb_path, host_port=host_port, device_port=device_port)