ANDROID_STUDIO_EMULATOR = 'android_studio_emulator'
CUTTLEFISH_EMULATOR = 'cuttlefish_emulator'
HARDWARE_DEVICE = 'hardware_device'

HASH_PLACEHOLDER = 'hash-placeholder'

UIDS_TO_FUZZ = [None, 1000000, 1001, 2000, 1000, 0]

REPEAT_SAME_PARAMETERS_MAX=2

DEFAULT_DEVICE_TO_USER = "127.0.0.1:6520"

LOCALHOST = 'localhost'
LOCALHOST_IP = '127.0.0.1'

ADB_DEVICES_COMMAND_LINE_BREAKAGE = 'List of devices attached'
NEW_LINE_BREAKAGE = '\n'
TAB_BREAKAGE = '\t'
WHITE_SPACE_BREAKAGE = ' '
CARRIAGE_RETURN_NEW_LINE_BREAKAGE = '\r\n'

STATS_FILE_NAME = 'stats.json'
TASKS = 'tasks'
CONFIG_FILE_NAME = 'config.json'
API_ACTIONS_FILE_NAME = 'api_actions.json'
API_DEFERRED_ACTIONS_FILE_NAME = 'api_deferred_actions.json'
APIS = 'APIs'
SERVICE_PROCESS_MAP = 'service_process_maps'
API_LISTS = 'lists/{}'.format(APIS)
SERVICE_PROCESS_MAP_LISTS = 'lists/{}'.format(SERVICE_PROCESS_MAP)
CONTENT_PROVIDER_LISTS = 'lists/content_provider_lists'
BROADCAST_LISTS = 'lists/broadcast_senders'

MERAKI_PKG_NAME = 'com.meraki.sm'

SYSTEM_UI_PKG_NAME = 'com.android.systemui'

FUZZER_APP_PKG_NAME = 'fuzzer.permission.uidchanger'

FUZZER_SERVICE_ACTION_NAME = 'fuzzer.permission.uidchanger.INVOKE'
FUZZER_INVOKATOR_SERVICE_NAME = 'Invokator'
FUZZER_APP_PRIVATE_FILES_PATH = '/data/user/0/{}/files'.format(FUZZER_APP_PKG_NAME)
FUZZER_APP_API_LIST_FILE_NAME = 'api-list.json'
FUZZER_APP_INVOCATION_RESULT_FILE_NAME = 'invocation-result.json'

FRIDA_SERVER_VERSION = '12.8.20'
FRIDA_SERVER = 'res/frida_server'
FRIDA_RELEASES_URL = 'https://github.com/frida/frida/releases/download/{}'.format(FRIDA_SERVER_VERSION)
FRIDA_SERVER_RAW_NAME = 'frida-server-{}-android-{}.xz'
FRIDA_SERVER_NAME = 'frida-server-{}-android-{}'
FRIDA_SERVER_PATH_ON_DEVICE = '/data/local/tmp/frida-server'
FRIDA_SERVER_EXECUTION_MODE = 777

FIRST_USER_ID = 1000000
FIRST_USER_ID_SWITCH_PROFILE = 10000000

ABI_ARM_V7A = 'armeabi-v7a'
ABI_ARM_64_V8A = 'arm64-v8a'
ABI_X86 = 'x86'
ABI_X86_64 = 'x86_64'

ARM = 'arm'
ARM64 = 'arm64'
X86 = 'x86'
X86_64 = 'x86_64'
UNKNOWN_CPU_ARCH = 'UNKNOWN_CPU_ARCHITECTURE'

API_LIST_FILE_NAME_SUFFIX = '_formatted.json'
ACTIONS_TEMPLATE_FILE_PATH = 'actions_template.json'
ORDERED_ACTION_TEMPLATE_FILE_NAME = 'ordered_action_template.json'


STATS_GENERIC = {
    'services_count': 0,
    'apis': 0,
    'done': 0,
    'pending': 0,
    'remaining': 0,
    'services': {}
}

STATS_SERVICE_GENERIC = {
    'apis': 0,
    'done': 0,
    'pending': 0,
    'remaining': 0,
    'remaining_list': [],
    'selected_list': [],
    'done_list': []
}

SERVICE_NAME_POSITION = 0
API_NAME_POSITION = 1
PARAMETERS_POSITION = 2
RETURN_TYPE_POSITION = 3


INVOKER_SERVICE = 'InvokerService'
SYSTEM_SERVER = 'system_server'
SERVICE_MANAGER = 'servicemanager'

INSTRUMENT_SERVICE_PROCESS_MAPPER_FILE = 'service_process_mapper.js'
INSTRUMENT_PERMISSION_MAPPER_FILE = 'permission_mapper.js'
INSTRUMENT_PERMISSION_MAPPER_REPLACE_VALUE = "SETUP_CONFIG_REPLACE_ME"

PERM_FUZZER_PREFIX = 'PERM_FUZZER_'

ACTION_CONTINUE = 'continue'
ACTION_START = 'clean_start'
ACTION_END = 'end'
ACTION_CHANGE_UID = 'change_uid'
ACTION_CHANGE_PID = 'change_pid'
ACTION_CHANGE_PARAMETERS = 'change_parameters'
ACTION_EXECUTE_DEFERRED = 'execute_deferred'
