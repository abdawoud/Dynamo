import pytest

from src.content_provider_fuzzing.commands.exec_command import ExecCommand, NonZeroExitCode


def test_shell_cmd():
    cmd = ExecCommand(args=['echo', 'abc'])
    output = cmd.execute()

    assert len(output) == 1
    assert output == ['abc']


def test_exit_code():
    cmd = ExecCommand(args=['echo', 'abc'], check_exit_code=True)
    cmd.execute()


def test_invalid_exit_code():
    cmd = ExecCommand(args=['cat', 'a_L_bc'], check_exit_code=True)
    with pytest.raises(NonZeroExitCode):
        cmd.execute()
