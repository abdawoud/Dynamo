from multiprocessing import Queue

import frida

from src.content_provider_fuzzing.execution_units.frida.frida_instrumentation_exec_unit import \
    FridaInstrumentationRequest, FridaInstrumentationExecUnit
from tests.sample_provider_tests.frida_tests.frida_test_setup import FridaTest


class TestFridaSystemServerInstrumentation(FridaTest):
    def test_frida_instrumentation(self):
        self.feedback_queue = Queue()

        instrumentation_request = FridaInstrumentationRequest(
            frida_device=frida.get_usb_device(),
            target_process_name='system_server',
            frida_js_script="""
Java.perform(function () {
    send('AAA');
});
""",
            on_message_function=self.__on_message
        )
        self.instrumentation_exec_unit = FridaInstrumentationExecUnit(instrumentation_request)
        self.instrumentation_exec_unit.setup()
        self.instrumentation_exec_unit.run()
        self.instrumentation_exec_unit.cleanup()

        assert self.feedback_queue.get(timeout=10) == {'type': 'send', 'payload': 'AAA'}

    def __on_message(self, message, data):
        self.feedback_queue.put(message)
