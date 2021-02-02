from pathlib import Path
from typing import List

import pytest

from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.commands.adb.adb_command import AdbCommand
from src.content_provider_fuzzing.commands.exec_command import ExecCommand, NonZeroExitCode


def test_adb_command():
    adb_cmd = AdbCommand(adb_path=get_adb_path(), args=['version'])
    output = adb_cmd.execute()
    assert 'Android Debug Bridge version' in output[0]


def test_adb_command_valid_exit_code():
    adb_cmd = AdbCommand(adb_path=get_adb_path(), args=['version'], check_exit_code=True)
    adb_cmd.execute()


def test_adb_command_invalid_exit_code():
    adb_cmd = AdbCommand(adb_path=get_adb_path(), args=['v_eX_rsion'], check_exit_code=True)
    with pytest.raises(NonZeroExitCode):
        adb_cmd.execute()


def test_adb_shell(adb_cmd_factory):
    cmd = adb_cmd_factory.shell(cmd='echo abc', check_exit_code=True)
    output_lines = cmd.execute()
    assert output_lines == ['abc']


def test_uninstall(adb_cmd_factory, device, test_app_pkg_name, test_apk_path):
    is_installed = device.is_package_installed(test_app_pkg_name)
    if not is_installed:
        cmd = adb_cmd_factory.install(test_apk_path)
        cmd.execute()

    cmd = adb_cmd_factory.uninstall(test_app_pkg_name)
    cmd.execute()

    assert not device.is_package_installed(test_app_pkg_name)


def test_install(adb_cmd_factory, device, test_app_pkg_name, test_apk_path):
    adb_cmd_factory = AdbCmdFactory(get_adb_path())

    is_installed = device.is_package_installed(test_app_pkg_name)
    if is_installed:
        cmd = adb_cmd_factory.uninstall(test_app_pkg_name)
        cmd.execute()

    cmd = adb_cmd_factory.install(test_apk_path)
    cmd.execute()

    assert device.is_package_installed(test_app_pkg_name)

    cmd = adb_cmd_factory.uninstall(test_app_pkg_name)
    cmd.execute()


def get_adb_path() -> Path:
    cmd = ExecCommand(args=['which', 'adb'])
    path = cmd.execute()[0]

    # Expand ~/abc -> $HOME_DIR/abc
    home_dir_path = Path().home().as_posix()
    path = path.replace('~', home_dir_path)

    return Path(path)


def is_substring_of_any_items(string_to_match, lines: List[str]):
    is_substring_of_item = map(lambda x: string_to_match in x, lines)
    return any(is_substring_of_item)


@pytest.fixture
def test_apk_path(test_app_pkg_name) -> Path:
    tool_dir = Path().resolve()
    return tool_dir / f'res/apks/{test_app_pkg_name}.apk'


@pytest.fixture
def test_app_pkg_name():
    return 'fuzzer.permission.uidchanger'
