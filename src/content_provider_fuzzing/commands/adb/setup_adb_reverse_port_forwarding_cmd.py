
from pathlib import Path

from src.content_provider_fuzzing.commands.adb.adb_command import AdbCommand


class SetupAdbReversePortForwardingCmd(AdbCommand):

    def __init__(self, adb_path: Path, host_port: int, device_port: int, check_exit_code=True):
        args = ['reverse', f'tcp:{host_port}', f'tcp:{device_port}']
        super().__init__(adb_path, args, check_exit_code)
