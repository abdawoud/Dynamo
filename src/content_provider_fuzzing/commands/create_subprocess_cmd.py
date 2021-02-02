import subprocess

from src.content_provider_fuzzing.commands.command import Command


class CreateSubprocessCmd(Command):

    def execute(self) -> subprocess.Popen:
        return subprocess.Popen(
            args=self.args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
