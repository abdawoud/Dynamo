from src.content_provider_fuzzing.fuzzing.permission_detection.enforcement_detector import EnforcementDetector


class ReadEnforcementDetector(EnforcementDetector):
    __PERMISSION_DENIAL_MATCHER = f'{EnforcementDetector._SECURITY_EXCEPTION}: Permission Denial: reading '
    __REQUIRES_MATCHER = 'requires '
    __END_MATCHER = ', or grantUriPermission()'

    def is_enforcement(self, thrown_exception: str) -> bool:
        is_permission_denial = thrown_exception.startswith(ReadEnforcementDetector.__PERMISSION_DENIAL_MATCHER)
        return is_permission_denial and ReadEnforcementDetector.__REQUIRES_MATCHER in thrown_exception

    def _extract_permission_names(self, parsed_message):
        # java.lang.SecurityException: Permission Denial:
        # reading de.cispa.testcontentprovider.ReadProtectedContentProvider
        # uri content://de.cispa.testcontentprovider.read_protected_provider/something/5
        # from pid=4636, uid=10134 requires de.cispa.testcontentprovider.permission.READ_SAMPLES,
        # or grantUriPermission()

        thrown_exception = parsed_message['thrownException']

        start_index = thrown_exception.index(self.__REQUIRES_MATCHER) + len(self.__REQUIRES_MATCHER)
        end_index = thrown_exception.index(self.__END_MATCHER)
        permission_name = thrown_exception[start_index:end_index]

        return [permission_name]
