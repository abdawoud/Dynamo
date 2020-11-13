import os
from utils import helpers


class Cuttelfish:
    def is_running_on_gcp(self):
        cmd = 'curl metadata.google.internal -i'
        cmd_prepared = helpers.prepare_command(cmd)
        out, _ = helpers.shell_execute(cmd_prepared)
        return "Google" in out

    def stop_process(self, path_to_bin: str):
        print("= Stopping Cuttlefish emulator...")
        cmd = "HOME={} {}/bin/stop_cvd >/dev/null 2>&1".format(path_to_bin, path_to_bin)
        os.system(cmd)
        print("+ Cuttlefish emulator is stopped!")

    def start_process(self, path_to_bin: str):
        print("= Running Cuttlefish emulator...")
        cmd = "HOME={} {}/bin/launch_cvd -daemon >/dev/null 2>&1".format(path_to_bin, path_to_bin)
        os.system(cmd)
        print("+ Cuttlefish emulator booted!")

    def is_running(self) -> bool:
        return True

    def __init__(self):
        pass