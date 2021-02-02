from src.content_provider_fuzzing.fuzzing.permission_detection.enforcement_detector import EnforcementDetector


class WriteEnforcementDetector(EnforcementDetector):
    __PERMISSION_DENIAL_MATCHER = f'{EnforcementDetector._SECURITY_EXCEPTION}: Permission Denial: writing '
    __REQUIRES_MATCHER = 'requires '
    __END_MATCHER = ', or grantUriPermission()'

    def is_enforcement(self, thrown_exception: str) -> bool:
        is_permission_denial = thrown_exception.startswith(WriteEnforcementDetector.__PERMISSION_DENIAL_MATCHER)
        return is_permission_denial and WriteEnforcementDetector.__REQUIRES_MATCHER in thrown_exception

    def _extract_permission_names(self, parsed_message):
        # java.lang.SecurityException: Permission Denial: writing com.android.providers.downloads.DownloadProvider
        # uri content://downloads/all_downloads from pid=2939, uid=10095 requires
        # android.permission.ACCESS_ALL_DOWNLOADS, or grantUriPermission()

        thrown_exception = parsed_message['thrownException']

        start_index = thrown_exception.index(self.__REQUIRES_MATCHER) + len(self.__REQUIRES_MATCHER)
        end_index = thrown_exception.index(self.__END_MATCHER)
        permission_name = thrown_exception[start_index:end_index]

        return [permission_name]
