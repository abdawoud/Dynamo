import subprocess
from typing import List

from src.content_provider_fuzzing.commands.command import Command


class NonZeroExitCode(Exception):
    def __init__(self, process: List[str], stdout: List[str], message):
        self.process = process
        self.stdout = stdout

        super().__init__(message)


class ExecCommand(Command):
    def __init__(self, args: List[str], check_exit_code=False):
        super().__init__(args)
        self.check_exit_code = check_exit_code

    def execute(self) -> List[str]:
        completed_proc = subprocess.run(
            args=self.args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        output = completed_proc.stdout
        output_lines = self._extract_lines_from_output(output)

        if self.check_exit_code and not completed_proc.returncode == 0:
            msg = f"Subprocess `{self.args}` returned non-zero exist code."
            raise NonZeroExitCode(self.args, output_lines, msg)

        return output_lines

    @staticmethod
    def _extract_lines_from_output(output):
        lines = [line.strip() for line in output.split('\n')]
        # output always ends with \n, so we have to delete the last entry
        return lines[:-1]
