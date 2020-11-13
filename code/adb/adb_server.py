from includes.constants import LOCALHOST, LOCALHOST_IP, ADB_DEVICES_COMMAND_LINE_BREAKAGE, \
    NEW_LINE_BREAKAGE, TAB_BREAKAGE
import subprocess
from utils import helpers


class AdbServer:
    RESOLVED_LOCAL_ADB = [LOCALHOST, LOCALHOST_IP]

    def get_connected_devices(self):
        if self.host in self.RESOLVED_LOCAL_ADB:
            out = subprocess.Popen([helpers.get_adb_path(), 'devices'],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        else:
            # @TODO: implement
            raise NotImplementedError

        stdout, stderr = out.communicate()

        if type(stdout) != str:
            stdout = stdout.decode()

        connected_devices = []

        if not stderr and stdout:
            tokens = stdout.split(ADB_DEVICES_COMMAND_LINE_BREAKAGE)
            if len(tokens) > 1:
                lines = tokens[1].split(NEW_LINE_BREAKAGE)
                for line in lines:
                    if line and 'device' in line:
                        device_id = line.split(TAB_BREAKAGE)[0].strip()
                        connected_devices.append(device_id)

            return connected_devices

        return []

    def __init__(self, host: str, port: int = None):
        self.host = host
        self.port = port
