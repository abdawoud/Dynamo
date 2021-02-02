
from abc import ABC, abstractmethod
from typing import List, Any

from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit


class CompositeExecUnit(ExecutionUnit, ABC):
    def setup(self):
        child_units = self.get_child_units()
        for unit in child_units:
            unit.setup()

    def run(self) -> List[Any]:
        child_units = self.get_child_units()
        results = []
        for unit in child_units:
            r = unit.run()
            results.append(r)
        return results

    def cleanup(self):
        child_units = self.get_child_units()
        for unit in reversed(child_units):
            unit.cleanup()

    @abstractmethod
    def get_child_units(self) -> List[ExecutionUnit]:
        pass
