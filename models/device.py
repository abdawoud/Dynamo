from code.adb.adb_connection import AdbConnection
from includes.constants import FUZZER_APP_PKG_NAME, FUZZER_APP_PRIVATE_FILES_PATH, \
    FUZZER_APP_API_LIST_FILE_NAME, API_LIST_FILE_NAME_SUFFIX, FIRST_USER_ID, FIRST_USER_ID_SWITCH_PROFILE, \
    TAB_BREAKAGE, WHITE_SPACE_BREAKAGE, NEW_LINE_BREAKAGE, PERM_FUZZER_PREFIX, FUZZER_SERVICE_ACTION_NAME, \
    FUZZER_INVOKATOR_SERVICE_NAME, FUZZER_APP_INVOCATION_RESULT_FILE_NAME, FRIDA_SERVER_PATH_ON_DEVICE
from utils.helpers import base64_encode, shell_execute, prepare_command, get_local_api_lists_path, file_exists, \
    format_api_lists
from utils import helpers
import time
import os
import uuid


class Device:
    def get_device_properties(self) -> str:
        if self.device_properties:
            return self.device_properties
        cmd = 'getprop'
        out, error = self.adb_connection.shell(cmd)
        if not error:
            self.device_properties = base64_encode(out)
            return self.device_properties
        raise ValueError

    def get_sdk_version(self) -> str:
        if self.sdk_version:
            return self.sdk_version
        cmd = 'getprop ro.build.version.sdk'
        out, error = self.adb_connection.shell(cmd)
        if not error:
            self.sdk_version = out.split(NEW_LINE_BREAKAGE)[0].strip()
            return self.sdk_version
        raise ValueError

    def get_abi(self) -> str:
        if self.abi:
            return self.abi
        cmd = 'getprop ro.product.cpu.abi'
        out, error = self.adb_connection.shell(cmd)
        if not error:
            self.abi = out.split(NEW_LINE_BREAKAGE)[0].strip()
            return self.abi
        raise ValueError

    def get_build_id(self) -> str:
        if self.build_id:
            return self.build_id
        cmd = 'getprop ro.build.id'
        out, error = self.adb_connection.shell(cmd)
        if not error:
            self.build_id = out.split(NEW_LINE_BREAKAGE)[0].strip()
            return self.build_id
        raise ValueError

    def get_os_release(self) -> str:
        if self.os_release:
            return self.os_release
        cmd = 'getprop ro.build.version.release'
        out, error = self.adb_connection.shell(cmd)
        if not error:
            os_release = out.split(NEW_LINE_BREAKAGE)[0].strip()
            return os_release
        raise ValueError

    def get_common_id(self) -> str:
        if self.common_id:
            return self.common_id
        abi = self.get_abi()
        build_id = self.get_build_id()
        self.common_id = "{}_{}".format(abi, build_id)
        return self.common_id

    def check_app_exists(self, pkg_name: str) -> bool:
        cmd = 'pm list packages {}'.format(pkg_name)
        out, error = self.adb_connection.shell(cmd)
        if not error:
            result = out.split(NEW_LINE_BREAKAGE)[0].strip()
            return pkg_name in result
        raise ValueError

    def file_chmod(self, path: str, mode: int) -> (str, str):
        cmd = 'chmod {} {}'.format(mode, path)
        out, error = self.adb_connection.shell(cmd)
        return out, error

    def is_frida_running(self) -> (str, str):
        cmd = 'frida-ps -D {}'.format(self.adb_connection.device_id)
        out, error = shell_execute(prepare_command(cmd))
        return "system_server" in out

    def start_frida_in_background(self, path: str) -> (str, str):
        cmd = '.{}'.format(path)
        out, error = self.adb_connection.shell(cmd, background=True)
        time.sleep(2)
        return out, error

    def start_fuzzing_app_main_activity(self, user_id: int = 0) -> (str, str):
        self.unlock()
        cmd = 'am force-stop --user {} {}'.format(user_id, FUZZER_APP_PKG_NAME)
        self.adb_connection.shell(cmd)

        cmd = 'am start -n {}/.MainActivity --user {}'.format(FUZZER_APP_PKG_NAME, user_id)
        out, error = self.adb_connection.shell(cmd)
        if not error:
            started = 'Starting: Intent' in out
            return started
        raise ValueError

    def create_on_device_fuzzing_private_files(self, user_id: int = 0) -> bool:
        files = [
            FUZZER_APP_API_LIST_FILE_NAME,
            FUZZER_APP_INVOCATION_RESULT_FILE_NAME
        ]
        pushed = 0
        for file in files:
            path_local = "/tmp/{}".format(file)
            if not file_exists(path_local):
                helpers.write_json_file(path_local, {})

            path_on_device = "/data/user/{}/{}/files/{}".format(user_id, FUZZER_APP_PKG_NAME,
                                                                file)
            out, _ = self.adb_connection.push(path_local, path_on_device)
            if "file pushed" in out:
                pushed = pushed + 1

        return pushed == len(files)

    def push_fuzzing_file(self, setup: dict = None, user_id: int = 0):
        temp_name = "{}{}.json".format(PERM_FUZZER_PREFIX, uuid.uuid4().hex[:6].upper())
        path_local = "/tmp/{}".format(temp_name)
        path_on_device = "/data/user/{}/{}/files/setup.json".format(user_id, FUZZER_APP_PKG_NAME)
        helpers.write_json_file(path_local, setup)
        out, _ = self.adb_connection.push(path_local, path_on_device)
        if "file pushed" in out:
            return True
        return False

    def pull_api_list(self):
        device_path = os.path.join(FUZZER_APP_PRIVATE_FILES_PATH, FUZZER_APP_API_LIST_FILE_NAME)
        local_path = get_local_api_lists_path(self.get_common_id())

        if file_exists(local_path) and "whoami" in helpers.read_json_file(local_path):
            local_path_tmp = local_path.replace(".json", API_LIST_FILE_NAME_SUFFIX)
            if not file_exists(local_path_tmp):
                format_api_lists(local_path)
            return True

        start_time = time.time()
        while True:
            out, _ = self.adb_connection.pull(device_path, local_path)
            if "file pulled" in out:
                if not helpers.read_json_file(local_path):
                    self.start_fuzzing_app_main_activity()
                    time.sleep(5)
                if helpers.read_json_file(local_path):
                    format_api_lists(local_path)
                    return True
            if time.time() - start_time > 20:
                return False
            time.sleep(1)


    def pull_invocation_result(self, user_id: int = 0):
        temp_name = "{}{}.json".format(PERM_FUZZER_PREFIX, uuid.uuid4().hex[:6].upper())
        local_path = os.path.join("/tmp", temp_name)
        try:
            path_on_device = "/data/user/{}/{}/files/invocation-result.json".format(user_id, FUZZER_APP_PKG_NAME)
            out, _ = self.adb_connection.pull(path_on_device, local_path)
            if "file pulled" in out and helpers.file_exists(local_path):
                return helpers.read_json_file(local_path)
            else:
                return None
        finally:
            helpers.read_file(local_path)

    def get_app_uid(self, pkg_name: str) -> int:
        cmd = "dumpsys package {} | grep userId=".format(pkg_name)
        timer = 0
        while timer != 20:
            out, error = self.adb_connection.shell(cmd)
            try:
                return int(out.split("=")[1])
            except:
                time.sleep(1)
                timer = timer + 1
        else:
            return -1

    def is_booting(self):
        pids = self.get_pid_by_process_name("bootanimation", True)
        booting = False
        for pid in pids:
            booting = pid > -1
            break
        return booting

    def is_cuttlefish_emulator(self):
        cmd = "getprop"
        out, error = self.adb_connection.shell(cmd)
        return "cuttlefish" in out

    def is_pixel_device_ready(self, process: str = "com.google.android.apps.maps"):
        if self.get_device_id() != '9B041FFAZ003KK':
            return True

        pids = self.get_pid_by_process_name(process, True)
        booting = False
        for pid in pids:
            booting = pid > -1
            break
        return booting

    def is_cuttlefish_emulator_ready(self, process: str = "com.android.traceur"):
        if not self.is_cuttlefish_emulator():
            return True

        pids = self.get_pid_by_process_name(process, True)
        booting = False
        for pid in pids:
            booting = pid > -1
            break
        return booting

    def resolve_uid(self, uid):
        new_uid = None
        if isinstance(uid, str):
            if ":" in uid:
                new_uid = int(uid.split(":")[0])
            else:
                new_uid = self.get_app_uid(uid)
        elif isinstance(uid, int):
            new_uid = uid
        return new_uid

    def get_user_id(self, uid):
        if uid is None:
            return 0
        if uid == FIRST_USER_ID:
            return int(int(uid) / FIRST_USER_ID)
        if uid == FIRST_USER_ID_SWITCH_PROFILE:
            return int(int(uid) / FIRST_USER_ID_SWITCH_PROFILE)
        uid = self.resolve_uid(uid)
        return int(int(uid) / FIRST_USER_ID)

    def get_pid_by_process_name(self, name: str, fuzzy_name: bool = False):
        pids = []
        cmd = "ps"
        out, error = self.adb_connection.shell(cmd)
        tokens = out.split(NEW_LINE_BREAKAGE)
        for t in tokens:
            _t = list(filter(None, t.split(WHITE_SPACE_BREAKAGE)))
            if len(_t) > 2:
                if fuzzy_name:
                    if name in _t[-1]:
                        pids.append(int(_t[1]))
                else:
                    if _t[-1] == name:
                        return int(_t[1])

        return pids if fuzzy_name else -1

    def get_user_id_of_second_profile(self) -> int:
        cmd = 'pm list users | grep UserInfo'
        user_id = 10
        try:
            out, error = self.adb_connection.shell(cmd)
            if "UserInfo" in out:
                users = out.split(NEW_LINE_BREAKAGE)
                for user in users:
                    if user == "":
                        continue
                    if user[user.find(":") + 1:user.rfind(":")] == "New User":
                        user_id = int(user[user.find("{") + 1:user.find(":")])
        finally:
            return user_id

    def get_package_name_by_pid(self, pid):
        try:
            cmd = 'ps'
            out, error = self.adb_connection.shell(cmd)
            tokens = out.split(NEW_LINE_BREAKAGE)
            for t in tokens:
                _t = list(filter(None, t.split(WHITE_SPACE_BREAKAGE)))
                if len(_t) > 2:
                    if _t[1].isdigit() and int(_t[1]) == int(pid):
                        return {
                            "name": _t[-1].replace("[", "").replace("]", ""),
                            "id": _t[0],
                            "pid": pid
                        }
        except:
            pass

        return {
            "name": None,
            "id": None,
            "pid": pid
        }

    def get_process_name_by_selinux_type(self, selinux_type: str) -> list:
        processes = []
        try:
            cmd = 'ps -Z'
            out, error = self.adb_connection.shell(cmd)
            tokens = out.split(NEW_LINE_BREAKAGE)
            for t in tokens:
                _t = list(filter(None, t.split(WHITE_SPACE_BREAKAGE)))
                if len(_t) > 2:
                    if _t[0] == selinux_type:
                        processes.append(_t[-1])
        except:
            pass

        return processes

    def get_frida_process_ids(self, process_name):
        cmd = "frida-ps -D {}".format(self.get_device_id())
        cmd_prepared = helpers.prepare_command(cmd)
        stdout, _ = helpers.shell_execute(cmd_prepared)
        lines = stdout.split("\n")
        pids = []
        for line in lines:
            tokens = [x for x in line.split(" ") if x]
            if len(tokens) == 0:
                continue
            if tokens[-1] == process_name:
                pids.append(int(tokens[0]))
        return pids

    def get_binder_services_list(self):
        services = []
        cmd = 'service list'
        out, error = self.adb_connection.shell(cmd)
        tokens = out.split(NEW_LINE_BREAKAGE)[1:-1]
        for t in tokens:
            _t = list(filter(None, t.split(WHITE_SPACE_BREAKAGE)))
            services.append(_t[0].split(TAB_BREAKAGE)[1].strip()[:-1])

        return services

    def get_package_name_by_uid(self, uid):
        template = {
            "name": None,
            "id": None,
            "uid": uid
        }
        if uid == 1000:
            template['name'] = "com.android.keychain"
            template['id'] = "system"
            return template

        if uid == 0:
            template['id'] = "root"
            return template

        profile = self.get_user_id(uid)
        if profile == 1:
            uid = uid - FIRST_USER_ID
            profile = 0

        if profile == 0:
            cmd = 'ps'
            out, error = self.adb_connection.shell(cmd)
            tokens = out.split(NEW_LINE_BREAKAGE)
            for t in tokens:
                _t = list(filter(None, t.split(WHITE_SPACE_BREAKAGE)))
                if len(_t) > 2:
                    if _t[1].isdigit() and _t[0] == "u0_a{}".format(uid-10000):
                        template['name'] = _t[-1]
                        template['id'] = t[0]
                        return template

        return template

    def invoke_service(self, user_id: int = 0, timeout=10):
        component_name = "{}/.{}".format(FUZZER_APP_PKG_NAME, FUZZER_INVOKATOR_SERVICE_NAME)
        cmd = 'am broadcast -a {} -n {} --user {}'.format(FUZZER_SERVICE_ACTION_NAME, component_name, user_id)
        out, _ = self.adb_connection.shell(cmd, timeout=timeout)
        return "Broadcast completed: result=" in out

    def reboot(self, wait: bool = False) -> (str, str):
        cmd = 'reboot'
        out, error = self.adb_connection.shell(cmd)

        if wait:
            while self.is_booting():
                print(self.get_common_id(), "Still booting...")
                time.sleep(2)
            time.sleep(3)

        return out, error

    def unlock(self) -> (str, str):
        cmd = 'input keyevent 82'
        out, error = self.adb_connection.shell(cmd)
        return out, error

    def kill_process(self, process_name: str, fuzzy_name: bool = False):
        pids = self.get_pid_by_process_name(process_name, fuzzy_name)
        if isinstance(pids, list):
            self.kill_processes(pids)
        else:
            self.kill_processes([pids])

    def kill_processes(self, pids: []):
        for pid in pids:
            if pid > -1:
                cmd = 'kill -9 {}'.format(pid)
                self.adb_connection.shell(cmd)

    def is_su_c_supported(self):
        return self.adb_connection.is_su_c_supported()

    def get_device_id(self):
        return self.adb_connection.device_id

    def __init__(self, adb_connection: AdbConnection):
        self.adb_connection = adb_connection
        self.device_properties = None
        self.sdk_version = None
        self.abi = None
        self.build_id = None
        self.os_release = None
        self.common_id = None
        self.allow_reboot = True
