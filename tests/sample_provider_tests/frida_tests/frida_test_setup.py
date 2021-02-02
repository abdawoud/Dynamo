import pytest

from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.execution_units.frida.frida_exec_unit import FridaExecUnit


class FridaTest:
    @pytest.fixture(autouse=True)
    def setup_and_teardown(self, adb_cmd_factory: AdbCmdFactory):
        self.adb_cmd_factory = adb_cmd_factory

        frida_exec_unit = FridaExecUnit(adb_cmd_factory)
        frida_exec_unit.setup()
        frida_exec_unit.run()
        yield frida_exec_unit
        frida_exec_unit.cleanup()
