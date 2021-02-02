import logging
import os
import subprocess
from subprocess import Popen, PIPE, STDOUT

from utils import helpers


class Cuttlefish:

    def __init__(self, cf_dir: str, reuse_instance=False):
        self.cf_dir = cf_dir
        self.reuse_instance = reuse_instance

        self.cf_server_process = None
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def is_running() -> bool:
        adb_path = helpers.get_adb_path()
        completed_proc = subprocess.run([adb_path, '-e', 'get-state'],
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        universal_newlines=True)
        return 'device' in completed_proc.stdout

    def wait_until_ready(self) -> bool:
        for line in self.cf_server_process.stdout:
            self.logger.debug(line)

            boot_complete_indicator = 'VIRTUAL_DEVICE_BOOT_COMPLETED'
            if boot_complete_indicator in line:
                self.logger.info("Cuttlefish instance booted successfully.")
                return True

        return False

    def start(self) -> bool:
        if self.is_running():
            if self.reuse_instance:
                self.logger.info("Reusing running cuttlefish instance")
                return False

        self.stop()

        self.logger.info("Starting cuttlefish instance")

        environment = self._create_env()
        binary_path = f'{self.cf_dir}/bin/launch_cvd'

        self.cf_server_process = Popen(args=[binary_path], stdout=PIPE, stderr=STDOUT, env=environment, cwd=self.cf_dir,
                                       universal_newlines=True)
        return True

    def stop(self) -> bool:
        environment = self._create_env()
        binary_path = f'{self.cf_dir}/bin/stop_cvd'

        completed_proc = subprocess.run([binary_path], env=environment, cwd=self.cf_dir,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        is_success = completed_proc.returncode == 0
        return is_success

    def _create_env(self):
        environment = os.environ.copy()
        environment['HOME'] = self.cf_dir
        return environment
