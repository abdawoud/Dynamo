
from pathlib import Path

from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory


class SampleProviderInstaller:
    APK_PATH = '/home/user/Documents/TestContentProvider/app/build/outputs/apk/debug/app-debug.apk'
    PACKAGE_NAME = 'de.cispa.testcontentprovider'

    def __init__(self, adb_cmd_factory: AdbCmdFactory):
        self.adb_cmd_factory = adb_cmd_factory

    def install(self):
        path = Path(SampleProviderInstaller.APK_PATH)
        install_cmd = self.adb_cmd_factory.install(path)
        install_cmd.execute()

    def uninstall(self):
        uninstall_cmd = self.adb_cmd_factory.uninstall(self.PACKAGE_NAME)
        uninstall_cmd.execute()
