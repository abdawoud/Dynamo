from src.adb.adb_server import AdbServer
from includes.constants import LOCALHOST, LOCALHOST_IP, WHITE_SPACE_BREAKAGE
from utils import helpers
import os
import subprocess
import uuid
import time


class AdbConnection:
    RESOLVED_LOCAL_ADB = [LOCALHOST, LOCALHOST_IP]

    def is_system_server_responsive(self):
        """
        command = '{} -s {} shell pm'.format(helpers.get_adb_path(), self.device_id)
        out, _ = helpers.shell_execute(helpers.prepare_command(command), timeout=3)
        print("list packages" in out)
        return "list packages" in out
        """
        return True

    def reboot_if_system_server_is_not_ready(self):
        rebooted = False
        while not self.is_system_server_responsive():
            if not rebooted:
                command = '{} -s {} reboot'.format(helpers.get_adb_path(), self.device_id)
                helpers.shell_execute(helpers.prepare_command(command))
                rebooted = True

            time.sleep(5)

    def set_adb_root(self):
        if self.adb_server.host in self.RESOLVED_LOCAL_ADB:
            out = ""
            if not self.is_su_c_supported():
                command = '{} -s {} root'.format(helpers.get_adb_path(), self.device_id)
                out = helpers.shell_execute(helpers.prepare_command(command))
            return out
        else:
            # @TODO: implement
            raise NotImplementedError

    '''
    ' @TODO: move this to Device class?
    '''
    def set_selinux_permissive(self):
        command_str = 'setenforce 0'
        out = self.shell(command_str, root=True, selinux_permissive=False)
        return out

    '''
    ' @TODO: move this to Device class?
    '''
    def disable_reflection_restrictions(self):
        self.reboot_if_system_server_is_not_ready()

        # For Android >= 10
        command_str = 'settings put global hidden_api_policy 1'
        self.shell(command_str, root=True, selinux_permissive=True)

        # For Android < 10
        command_str = 'settings put global hidden_api_policy_pre_p_apps 1'
        self.shell(command_str, root=True, selinux_permissive=True)
        command_str = 'settings put global hidden_api_policy_p_apps 1'
        self.shell(command_str, root=True, selinux_permissive=True)

    def is_su_c_supported(self):
        is_enforced = False
        try:
            command_str = '{} -s {} shell su -c "getenforce"'.format(helpers.get_adb_path(), self.device_id)
            command_array = command_str.split(WHITE_SPACE_BREAKAGE)
            out, _ = helpers.shell_execute(command_array)
            is_enforced = 'Enforcing' in out or "Permissive" in out
        except:
            pass
        return is_enforced

    def shell(self, command: str, root: bool = True, selinux_permissive: bool = True,
              background: bool = False, timeout: int = 0):
        self.reboot_if_system_server_is_not_ready()

        if root:
            self.set_adb_root()

        if selinux_permissive:
            self.set_selinux_permissive()

        if self.adb_server.host in self.RESOLVED_LOCAL_ADB:
            if background:
                if self.is_su_c_supported():
                    command_str = "{} -s {} shell su -c '{}' &".format(helpers.get_adb_path(),
                                                                       self.device_id, command)
                else:
                    command_str = "{} -s {} shell '{}' &".format(helpers.get_adb_path(), self.device_id, command)
                os.system(command_str)
                return None, None
            else:
                if self.is_su_c_supported():
                    command_str = '{} -s {} shell su -c "{}"'.format(helpers.get_adb_path(), self.device_id, command)
                else:
                    command_str = '{} -s {} shell {}'.format(helpers.get_adb_path(), self.device_id, command)

                command_array = command_str.split(WHITE_SPACE_BREAKAGE)
                return helpers.shell_execute(command_array, timeout)
        else:
            # @TODO: implement
            raise NotImplementedError

    def push(self, local_path, device_path):
        self.reboot_if_system_server_is_not_ready()

        if self.adb_server.host in self.RESOLVED_LOCAL_ADB:
            if self.is_su_c_supported():
                tmp_file_name = uuid.uuid4()
                tmp_path = '/data/local/tmp/{}'.format(tmp_file_name)

                command_str = '{} -s {} push {} {}'.format(helpers.get_adb_path(), self.device_id, local_path, tmp_path)
                command_array = command_str.split(WHITE_SPACE_BREAKAGE)
                out = helpers.shell_execute(command_array)

                command_str = '{} -s {} shell su -c "mount -o rw,remount /data"'.format(helpers.get_adb_path(),
                                                                                        self.device_id)
                command_array = command_str.split(WHITE_SPACE_BREAKAGE)
                helpers.shell_execute(command_array)

                command_str = '{} -s {} shell su -c "mv {} {}"'.format(helpers.get_adb_path(),
                                                                       self.device_id, tmp_path, device_path)
                command_array = command_str.split(WHITE_SPACE_BREAKAGE)
                helpers.shell_execute(command_array)
            else:
                self.set_adb_root()
                self.set_selinux_permissive()

                command_str = '{} -s {} push {} {}'.format(helpers.get_adb_path(), self.device_id,
                                                           local_path, device_path)
                command_array = command_str.split(WHITE_SPACE_BREAKAGE)
                out = helpers.shell_execute(command_array)
            return out
        else:
            # @TODO: implement
            raise NotImplementedError

    def pull(self, device_path, local_path):
        self.reboot_if_system_server_is_not_ready()

        if self.adb_server.host in self.RESOLVED_LOCAL_ADB:
            if self.is_su_c_supported():
                tmp_device_path = '/sdcard/{}'.format(device_path.split("/")[-1])
                command_str = '{} -s {} shell su -c "mount -o rw,remount /data"'.format(helpers.get_adb_path(),
                                                                                        self.device_id)
                command_array = command_str.split(WHITE_SPACE_BREAKAGE)

                helpers.shell_execute(command_array)
                command_str = '{} -s {} shell su -c "cp {} {}"'.format(helpers.get_adb_path(), self.device_id,
                                                                       device_path, tmp_device_path)
                command_array = command_str.split(WHITE_SPACE_BREAKAGE)
                helpers.shell_execute(command_array)

                command_str = '{} -s {} pull {} {}'.format(helpers.get_adb_path(), self.device_id, tmp_device_path,
                                                           local_path)
                command_array = command_str.split(WHITE_SPACE_BREAKAGE)
                return helpers.shell_execute(command_array)
            else:
                self.set_adb_root()
                self.set_selinux_permissive()
                command_str = '{} -s {} pull {} {}'.format(helpers.get_adb_path(), self.device_id, device_path,
                                                           local_path)

                command_array = command_str.split(WHITE_SPACE_BREAKAGE)
                return helpers.shell_execute(command_array)
        else:
            # @TODO: implement
            raise NotImplementedError

    def install(self, path: str) -> (bool, str):
        self.reboot_if_system_server_is_not_ready()

        if self.adb_server.host in self.RESOLVED_LOCAL_ADB:
            command_str = '{} -s {} install {}'.format(helpers.get_adb_path(), self.device_id, path)
            command_array = command_str.split(WHITE_SPACE_BREAKAGE)
            helpers.shell_execute(command_array)
        else:
            # @TODO: implement
            raise NotImplementedError

    def uninstall(self, pkg_name: str) -> (bool, str):
        self.reboot_if_system_server_is_not_ready()

        if self.adb_server.host in self.RESOLVED_LOCAL_ADB:
            command_str = '{} -s {} uninstall {}'.format(helpers.get_adb_path(), self.device_id, pkg_name)
            command_array = command_str.split(WHITE_SPACE_BREAKAGE)
            return helpers.shell_execute(command_array)
        else:
            # @TODO: implement
            raise NotImplementedError

    def __init__(self, adb_server: AdbServer, device_id: str):
        self.adb_server = adb_server
        self.device_id = device_id

        # Prepare the adb connection for following operations!
        self.set_adb_root()
        self.set_selinux_permissive()
        self.disable_reflection_restrictions()
