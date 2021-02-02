import logging
from typing import Callable

import frida

from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit


class FridaSpawnGatingExecUnit(ExecutionUnit):
    def __init__(self, target_process_name: str, function_to_run_before_spawning: Callable):
        self.target_process_name = target_process_name
        self.function_to_run_before_spawning = function_to_run_before_spawning

        self.frida_device = None
        self.logger = logging.getLogger(__name__)

    def setup(self):
        self.frida_device = frida.get_usb_device()
        self.frida_device.on('spawn-added', self._on_spawn_added)

    def run(self):
        self.logger.info(f"Enabling spawn gating")
        self.frida_device.enable_spawn_gating()

    def cleanup(self):
        self.frida_device.disable_spawn_gating()

    def _on_spawn_added(self, spawn):
        self.logger.info(f"Spawn gating `{spawn}`")
        try:
            if spawn.identifier == self.target_process_name:
                self.function_to_run_before_spawning(spawn.pid)

            self.frida_device.resume(spawn.pid)

        except Exception as e:
            self.logger.error(f"Frida error: {spawn} - {e}")
