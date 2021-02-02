import time
from abc import ABC

from includes.constants import FRIDA_SERVER_PATH_ON_DEVICE, FRIDA_SERVER_EXECUTION_MODE, FUZZER_APP_PKG_NAME
from models.device import Device
from utils import helpers
from utils.log import Logger


class BaseWorker(ABC):

    def __init__(self, device: Device):
        self.device = device
        self.device_common_id = self.device.get_common_id()
        self.logger = Logger(self.device)
        self.exit_thread = False

    def __del__(self):
        self.logger.ilog("Exiting....")

    def prepare(self):
        success = self.install_and_run_frida()
        if not success:
            error = "Cannot run frida!"
            self.logger.elog(error)
            raise Exception(error)
        else:
            self.logger.ilog("Frida is installed and running")

    def install_and_run_frida(self) -> bool:
        if self.device.is_frida_running():
            self.logger.ilog("Frida is running!")
            return True

        abi = self.device.get_abi()
        path = helpers.get_frida_server(abi)
        self.device.adb_connection.push(path, FRIDA_SERVER_PATH_ON_DEVICE)
        self.device.file_chmod(FRIDA_SERVER_PATH_ON_DEVICE, FRIDA_SERVER_EXECUTION_MODE)
        self.device.start_frida_in_background(FRIDA_SERVER_PATH_ON_DEVICE)

        time.sleep(2)

        if self.device.is_frida_running():
            self.logger.ilog("Frida is running!")
            return True

        return False

    def install_app(self, pkg_name: str):
        path = helpers.get_app_info(pkg_name)

        pkg_installed = self.device.check_app_exists(pkg_name)
        reinstall = False

        if pkg_installed:
            if pkg_name == FUZZER_APP_PKG_NAME:
                stats = helpers.get_stats(self.device_common_id)
                if stats and 'apk_hash' in stats:
                    apk_hash = helpers.sha256sum(path)
                    if stats['apk_hash'] == apk_hash:
                        print(self.device.get_device_id(), "APks checksums matche...")
                        return True

                reinstall = True
            else:
                return True

        if reinstall:
            print(self.device.get_device_id(), "Uninstalling the app...")
            self.device.adb_connection.uninstall(pkg_name)

        stats = helpers.get_stats(self.device_common_id)
        if stats:
            apk_hash = helpers.sha256sum(path)
            stats['apk_hash'] = apk_hash
            helpers.persist_stats(self.device_common_id, stats)

        print(self.device.get_device_id(), "Installing the app...")
        self.device.adb_connection.install(path)

        return self.device.check_app_exists(pkg_name)
