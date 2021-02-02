from typing import List

from src.content_provider_fuzzing.cp_api_models import ApiFuzzingResult


class ManifestEnforcementDetector:
    __SECURITY_EXCEPTION = 'java.lang.SecurityException'
    __PERMISSION_DENIAL_MATCHER = f'{__SECURITY_EXCEPTION}: Permission Denial: opening provider '
    __REQUIRES_MATCHER = 'requires '
    __OR_MATCHER = ' or '

    @staticmethod
    def is_manifest_enforcement(thrown_exception: str) -> bool:
        is_permission_denial = thrown_exception.startswith(ManifestEnforcementDetector.__PERMISSION_DENIAL_MATCHER)
        return is_permission_denial and ManifestEnforcementDetector.__REQUIRES_MATCHER in thrown_exception and \
               ManifestEnforcementDetector.__OR_MATCHER in thrown_exception

    @staticmethod
    def is_security_exception(thrown_exception: str):
        return thrown_exception.startswith(ManifestEnforcementDetector.__SECURITY_EXCEPTION)

    def extract_fuzzing_result_with_permissions(self, parsed_message):
        return self.__extract_fuzzing_result(
            parsed_message=parsed_message,
            permission_names=self.__extract_permission_names(parsed_message)
        )

    def extract_fuzzing_result_no_permissions(self, parsed_message):
        return self.__extract_fuzzing_result(parsed_message=parsed_message, permission_names=[])

    @staticmethod
    def __extract_fuzzing_result(parsed_message, permission_names: List[str]):
        return ApiFuzzingResult(
            input=parsed_message['input'],
            permission_names=permission_names,
            thrown_exception=parsed_message['thrownException'],
            stacktrace=parsed_message['stackTrace']
        )

    def __extract_permission_names(self, parsed_message):
        # java.lang.SecurityException: Permission Denial: opening provider
        # de.cispa.testcontentprovider.RwProtectedContentProvider from
        # ProcessRecord{2935ac6 3236:saarland.cispa.contentproviderfuzzer/u0a98} (pid=3236, uid=10098)
        # requires de.cispa.testcontentprovider.permission.READ_SAMPLES or
        # de.cispa.testcontentprovider.permission.WRITE_SAMPLES

        thrown_exception = parsed_message['thrownException']
        read_permission = self.__extract_read_permission_name(thrown_exception)
        write_permission = self.__extract_write_permission_name(thrown_exception)
        return [read_permission, write_permission]

    def __extract_read_permission_name(self, thrown_exception) -> str:
        start_index = thrown_exception.index(self.__REQUIRES_MATCHER) + len(self.__REQUIRES_MATCHER)
        end_index = thrown_exception.index(self.__OR_MATCHER)
        return thrown_exception[start_index: end_index]

    def __extract_write_permission_name(self, thrown_exception):
        second_perm_start_index = thrown_exception.index(self.__OR_MATCHER) + len(self.__OR_MATCHER)
        return thrown_exception[second_perm_start_index:]
