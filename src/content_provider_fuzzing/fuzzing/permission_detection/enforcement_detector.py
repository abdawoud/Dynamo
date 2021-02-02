from abc import ABC, abstractmethod
from typing import List

from src.content_provider_fuzzing.cp_api_models import ApiFuzzingResult


class EnforcementDetector(ABC):
    _SECURITY_EXCEPTION = 'java.lang.SecurityException'

    @abstractmethod
    def is_enforcement(self, thrown_exception: str) -> bool:
        pass

    @abstractmethod
    def _extract_permission_names(self, parsed_message) -> List[str]:
        pass

    @staticmethod
    def is_security_exception(thrown_exception: str):
        return thrown_exception.startswith(EnforcementDetector._SECURITY_EXCEPTION)

    def extract_fuzzing_result_with_permissions(self, parsed_message):
        return self.extract_fuzzing_result(
            parsed_message=parsed_message,
            permission_names=self._extract_permission_names(parsed_message)
        )

    def extract_fuzzing_result_no_permissions(self, parsed_message):
        return self.extract_fuzzing_result(parsed_message=parsed_message, permission_names=[])

    @staticmethod
    def extract_fuzzing_result(parsed_message, permission_names: List[str]):
        return ApiFuzzingResult(
            input=parsed_message['input'],
            permission_names=permission_names,
            thrown_exception=parsed_message['thrownException'],
            stacktrace=parsed_message['stackTrace']
        )
