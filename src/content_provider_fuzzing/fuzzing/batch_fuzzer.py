import json
from typing import Dict

from src.content_provider_fuzzing.deencoders.json_decoder import JsonDecoder
from src.content_provider_fuzzing.fuzzing.fuzzer import Fuzzer


class FuzzingFailed(Exception):
    pass


class BatchFuzzer(Fuzzer):
    MSG_DONE_FUZZING = "Done fuzzing"
    MSG_DONE_SENDING_RESULTS = "Done sending"

    MSG_ASK_FOR_RESULTS = "Send results"

    def _fuzz(self, fuzzing_job: Dict) -> None:
        self.__ask_for_results()
        self.__get_and_process_results()

    def __ask_for_results(self):
        done_fuzzing_msg = self.connection_to_fuzzer.receive_message()
        if not done_fuzzing_msg == self.MSG_DONE_FUZZING:
            raise FuzzingFailed()

        self.connection_to_fuzzer.send_message(self.MSG_ASK_FOR_RESULTS)

    def __get_and_process_results(self):
        message = self.connection_to_fuzzer.receive_message()
        while not self.__received_all_results(message):
            self.__process_results(message)

            self.connection_to_fuzzer.send_ack()
            message = self.connection_to_fuzzer.receive_message()

    def __received_all_results(self, message: str):
        return message == self.MSG_DONE_SENDING_RESULTS

    def __process_results(self, message: str):
        parsed_message = json.loads(message, cls=JsonDecoder)
        for fuzz_result in parsed_message:
            self._process_fuzz_result(fuzz_result)
