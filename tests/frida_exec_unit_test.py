from src.content_provider_fuzzing.commands.exec_command import ExecCommand
from src.content_provider_fuzzing.execution_units.frida.frida_exec_unit import FridaExecUnit


def test_frida_exec_unit(adb_cmd_factory):
    exec_unit = FridaExecUnit(adb_cmd_factory)
    exec_unit.setup()

    exec_unit.run()

    cmd = ExecCommand(['frida-ps', '-U'])
    output = cmd.execute()
    assert 'PID' in output[0] and 'Name' in output[0]

    exec_unit.cleanup()
