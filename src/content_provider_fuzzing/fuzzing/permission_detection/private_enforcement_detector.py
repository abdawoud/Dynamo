from src.content_provider_fuzzing.fuzzing.permission_detection.enforcement_detector import EnforcementDetector


class PrivateEnforcementDetector(EnforcementDetector):
    __PERMISSION_DENIAL_MATCHER = f'{EnforcementDetector._SECURITY_EXCEPTION}: Permission Denial: opening provider '
    __NOT_EXPORTED_MATCHER = ' that is not exported from UID '

    def is_enforcement(self, thrown_exception: str) -> bool:
        is_permission_denial = thrown_exception.startswith(PrivateEnforcementDetector.__PERMISSION_DENIAL_MATCHER)
        return is_permission_denial and PrivateEnforcementDetector.__NOT_EXPORTED_MATCHER in thrown_exception

    def _extract_permission_names(self, parsed_message):
        # java.lang.SecurityException: Permission Denial: opening provider
        # com.android.inputmethod.dictionarypack.DictionaryProvider from
        # ProcessRecord{47cf26 2939:saarland.cispa.contentproviderfuzzer/u0a95} (pid=2939, uid=10095)
        # that is not exported from UID 10090
        return ['not_exported']
