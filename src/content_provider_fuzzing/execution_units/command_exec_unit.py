
from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit


class CommandExecUnit(ExecutionUnit):
    def __init__(self, command):
        self.command = command

    def setup(self):
        pass

    def run(self):
        self.command.execute()

    def cleanup(self):
        pass
