import pytest

from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.emulator.device import Device
from tests.commands.adb.adb_command_test import get_adb_path


@pytest.fixture(scope="session")
def adb_cmd_factory():
    return AdbCmdFactory(get_adb_path())


@pytest.fixture(scope="session")
def device(adb_cmd_factory):
    return Device(adb_cmd_factory)
