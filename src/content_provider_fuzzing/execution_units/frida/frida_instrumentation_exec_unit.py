from dataclasses import dataclass
from typing import List, Callable, Any

from frida.core import Session

from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit


@dataclass
class FridaInstrumentationRequest:
    frida_device: Any
    target_process_name: str
    frida_js_script: str
    on_message_function: Callable


class FridaInstrumentationExecUnit(ExecutionUnit):

    def __init__(self, instrumentation_request: FridaInstrumentationRequest):
        self.instrumentation_request = instrumentation_request

        self.active_session: List[Session] = []

    def setup(self):
        pass

    def run(self):
        target_process_name = self.instrumentation_request.target_process_name
        session = self.instrumentation_request.frida_device.attach(target_process_name)

        self.active_session.append(session)

        frida_js_script = self.instrumentation_request.frida_js_script
        script = session.create_script(frida_js_script)

        on_message_function = self.instrumentation_request.on_message_function
        script.on('message', on_message_function)
        script.load()

    def cleanup(self):
        for session in self.active_session:
            session.detach()
        self.active_session.clear()

