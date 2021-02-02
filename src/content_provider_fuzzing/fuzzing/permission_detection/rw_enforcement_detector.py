from src.content_provider_fuzzing.fuzzing.permission_detection.enforcement_detector import EnforcementDetector


class RwEnforcementDetector(EnforcementDetector):
    __PERMISSION_DENIAL_MATCHER = f'{EnforcementDetector._SECURITY_EXCEPTION}: Permission Denial: opening provider '
    __REQUIRES_MATCHER = 'requires '
    __OR_MATCHER = ' or '

    def is_enforcement(self, thrown_exception: str) -> bool:
        is_permission_denial = thrown_exception.startswith(RwEnforcementDetector.__PERMISSION_DENIAL_MATCHER)
        return is_permission_denial and RwEnforcementDetector.__REQUIRES_MATCHER in thrown_exception and \
               RwEnforcementDetector.__OR_MATCHER in thrown_exception

    def _extract_permission_names(self, parsed_message):
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
