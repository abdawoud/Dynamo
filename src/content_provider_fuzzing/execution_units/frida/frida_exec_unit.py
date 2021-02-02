import logging
import lzma
import os
import threading
from pathlib import Path
from time import sleep

import requests

from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit


class FridaExecUnit(ExecutionUnit):
    frida_url = 'https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-x86_64.xz'

    def __init__(self, adb_cmd_factory: AdbCmdFactory, frida_server_version='14.2.8') -> None:
        self.adb_cmd_factory = adb_cmd_factory
        self.frida_server_version = frida_server_version

        self.logger = logging.getLogger(__name__)
        self.cache_dir = self._get_cache_dir()

        binary_name = f'frida-server-{self.frida_server_version}-android-x86_64'
        self.binary_path = self.cache_dir / binary_name

        self.frida_process = None

    def setup(self):
        if not self._is_frida_present():
            assert self._download()
            assert self._extract()

        # Installs - https://frida.re/docs/android/
        cmd = self.adb_cmd_factory.root()
        cmd.execute()

        cmd = self.adb_cmd_factory.adb(args=['setenforce', '0'], check_exit_code=False)
        cmd.execute()

        on_device_path = '/data/local/tmp/frida-server'

        cmd = self.adb_cmd_factory.adb(args=['push', self.binary_path.as_posix(), on_device_path],
                                       check_exit_code=True)
        cmd.execute()

        cmd = self.adb_cmd_factory.shell(cmd=f'chmod 755 {on_device_path}')
        cmd.execute()

    def run(self):
        cmd = self.adb_cmd_factory.create_on_device_subprocess(binary_path='/data/local/tmp/frida-server')
        self.frida_process = cmd.execute()

        sleep(1)

        # Automatically stops if stdout return EOF
        frida_monitoring_thread = threading.Thread(target=self._monitor_frida_process_output)
        frida_monitoring_thread.start()

    def cleanup(self):
        if self.frida_process is not None:
            self.frida_process.terminate()

        cmd = self.adb_cmd_factory.unroot()
        cmd.execute()

    def _monitor_frida_process_output(self):
        for line in self.frida_process.stdout:
            self.logger.error(line)

    def _is_frida_present(self) -> bool:
        return self.binary_path.exists()

    @staticmethod
    def _get_cache_dir():
        # https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
        cache_dir = os.environ.get('XDG_CACHE_HOME')
        if cache_dir is None:
            home_dir = os.environ.get('HOME')
            cache_dir = Path(home_dir) / '.cache'
        else:
            cache_dir = Path(cache_dir)

        dynamo_cache_dir = cache_dir / 'dynamo'
        frida_cache_dir = dynamo_cache_dir / 'frida'

        frida_cache_dir.mkdir(parents=True, exist_ok=True)
        return frida_cache_dir

    def _download(self) -> bool:
        # Download frida
        download_url = self.frida_url.format(version=self.frida_server_version)
        file_path = self.binary_path.as_posix() + '.xz'
        request = requests.get(download_url)
        with open(file_path, 'wb') as f:
            f.write(request.content)

        return True

    def _extract(self) -> bool:
        archive_path = self.cache_dir / (self.binary_path.name + '.xz')

        is_success = False
        with lzma.open(archive_path.as_posix()) as compressed_file:
            with open(self.binary_path.as_posix(), 'wb') as extracted_file:
                compressed_content = compressed_file.read()
                extracted_file.write(compressed_content)

                is_success = True

        # Remove archive
        archive_path.unlink()
        return is_success
