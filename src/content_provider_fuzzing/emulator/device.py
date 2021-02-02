from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory


class Device:
    def __init__(self, adb_cmd_factory: AdbCmdFactory):
        self.adb_cmd_factory = adb_cmd_factory

    def is_package_installed(self, package_name: str) -> bool:
        return package_name in self._get_installed_packages()

    def _get_installed_packages(self):
        shell_cmd = self.adb_cmd_factory.shell(cmd='cmd package list packages')
        installed_packages = shell_cmd.execute()

        # format: [package:com.android.inputmethod.latin, ...]
        return map(lambda x: x.replace('package:', ''), installed_packages)
