import subprocess
import os
from base64 import b64encode
from pathlib import Path
import wget
import lzma
from typing import Any
import json
import re
import copy
import hashlib

from includes.constants import WHITE_SPACE_BREAKAGE, CARRIAGE_RETURN_NEW_LINE_BREAKAGE, NEW_LINE_BREAKAGE, API_LISTS, \
    CONTENT_PROVIDER_LISTS, BROADCAST_LISTS, FRIDA_SERVER_VERSION, FRIDA_SERVER, \
    ABI_ARM_V7A, ABI_ARM_64_V8A, ABI_X86, ABI_X86_64, ARM, ARM64, X86, X86_64, UNKNOWN_CPU_ARCH, FRIDA_RELEASES_URL, \
    FRIDA_SERVER_RAW_NAME, API_LIST_FILE_NAME_SUFFIX, TASKS, APIS, CONFIG_FILE_NAME, STATS_FILE_NAME, \
    STATS_GENERIC, STATS_SERVICE_GENERIC, API_ACTIONS_FILE_NAME, ACTIONS_TEMPLATE_FILE_PATH, \
    SERVICE_PROCESS_MAP_LISTS, ORDERED_ACTION_TEMPLATE_FILE_NAME, UIDS_TO_FUZZ, API_DEFERRED_ACTIONS_FILE_NAME

from models.task import Task, get_api_name, get_parameters, get_service_name
from src.generator.parameters_generator import ParametersGenerator


def shell_execute(command: list, timeout: int = 0) -> (str, str):
    environment = os.environ.copy()
    environment['PATH'] = f"{environment['PATH']}:{environment['HOME']}/.local/bin/"

    out = subprocess.Popen(command, env=environment,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)

    if timeout == 0:
        stdout, stderror = out.communicate()
    else:
        try:
            stdout, stderror = out.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as e:
            stdout = ""
            stderror = str(e)
    if type(stdout) != str:
        stdout = stdout.decode()

    if stdout:
        stdout = stdout.replace(CARRIAGE_RETURN_NEW_LINE_BREAKAGE, NEW_LINE_BREAKAGE)
    return stdout, stderror


def get_custom_parameters_file():
    path = os.path.join(get_project_root_path(), "res/custom-params-info/custom_parameters.json")
    if not file_exists(path):
        dir_path = "/".join(path.split("/")[0:-1])
        if not dir_exists(dir_path):
            create_dir(dir_path)
        write_json_file(path, {})
    custom_params_info = read_json_file(path)
    return custom_params_info


def persist_custom_parameters_file(custom_parameters_info):
    path = os.path.join(get_project_root_path(), "res/custom-params-info/custom_parameters.json")
    write_json_file(path, custom_parameters_info)


def get_stats(common_device_id):
    task_dir_name = get_tasks_dir_path(common_device_id, APIS)
    stats_file_path = os.path.join(task_dir_name, STATS_FILE_NAME)
    stats = read_json_file(stats_file_path)
    return stats


def persist_stats(common_device_id, stats):
    task_dir_name = get_tasks_dir_path(common_device_id, APIS)
    stats_file_path = os.path.join(task_dir_name, STATS_FILE_NAME)
    write_json_file(stats_file_path, stats)


def clean_stats(common_device_id: str):
    stats = get_stats(common_device_id)

    for service in stats['services']:
        if stats['services'][service]['pending'] > 0:
            for pending_api in reversed(stats['services'][service]['selected_list']):
                stats['services'][service]['remaining_list'].insert(0, pending_api)
                stats['services'][service]['pending'] = stats['services'][service]['pending'] - 1
                stats['services'][service]['remaining'] = stats['services'][service]['remaining'] + 1
                stats['pending'] = stats['pending'] - 1
                stats['remaining'] = stats['remaining'] + 1
            stats['services'][service]['selected_list'] = []

    persist_stats(common_device_id, stats)


def reset_api_stats(common_device_id: str, service: str, api: str):
    stats = get_stats(common_device_id)

    formatted_api_prefix = "{}|{}".format(service, api)

    tasks = []

    all_apis_list = []
    all_apis_list.extend(stats['services'][service]['done_list'])
    all_apis_list.extend(stats['services'][service]['remaining_list'])
    all_apis_list.extend(stats['services'][service]['selected_list'])

    for api_ in all_apis_list:
        if api_.startswith(formatted_api_prefix):
            task = Task(APIS, api_)
            task.set_api(get_api_name(api_))
            task.set_service(get_service_name(api_))
            tasks.append(task)

    for api_ in stats['services'][service]['done_list']:
        if api_.startswith(formatted_api_prefix):
            stats['services'][service]['remaining_list'].insert(0, api_)
            stats['services'][service]['done_list'].remove(api_)

            stats['services'][service]['done'] = stats['services'][service]['done'] - 1
            stats['services'][service]['remaining'] = stats['services'][service]['remaining'] + 1
            stats['done'] = stats['done'] - 1
            stats['remaining'] = stats['remaining'] + 1

    persist_stats(common_device_id, stats)

    for task in tasks:
        config = get_task_config(task, common_device_id)
        config['parameters_done'] = {}
        config['uids_done'] = []
        config['classes'] = []
        config['phase_name'] = None
        config['errors'] = {}
        config['pids'] = []
        config['pids_done'] = []
        if 'done' in config:
            del config['done']
        persist_task_config(task, common_device_id, config)

        remove_file(get_deferred_actions_file_path(task, common_device_id))
        remove_file(get_api_actions_file_path(task, common_device_id))


def reset_service_stats(common_device_id: str, service: str):
    stats = get_stats(common_device_id)

    tasks = []

    all_apis_list = []
    all_apis_list.extend(stats['services'][service]['done_list'])
    all_apis_list.extend(stats['services'][service]['remaining_list'])
    all_apis_list.extend(stats['services'][service]['selected_list'])

    for api_ in all_apis_list:
        task = Task(APIS, api_)
        task.set_api(get_api_name(api_))
        task.set_service(get_service_name(api_))
        tasks.append(task)

    for api_ in stats['services'][service]['done_list']:
        stats['services'][service]['remaining_list'].insert(0, api_)
        if api_ in stats['services'][service]['done_list']:
            del stats['services'][service]['done_list'][0]

        stats['services'][service]['done'] = stats['services'][service]['done'] - 1
        stats['services'][service]['remaining'] = stats['services'][service]['remaining'] + 1
        stats['done'] = stats['done'] - 1
        stats['remaining'] = stats['remaining'] + 1

        tasks.append(Task(APIS, api_))

    persist_stats(common_device_id, stats)

    for task in tasks:
        config = get_task_config(task, common_device_id)
        if config:
            config['parameters_done'] = {}
            config['uids_done'] = []
            config['classes'] = []
            config['phase_name'] = None
            config['errors'] = {}
            config['pids'] = []
            config['pids_done'] = []
            if 'done' in config:
                del config['done']
            persist_task_config(task, common_device_id, config)

        remove_file(get_deferred_actions_file_path(task, common_device_id))
        remove_file(get_api_actions_file_path(task, common_device_id))


def prepare_command(command: str) -> list:
    return command.split(WHITE_SPACE_BREAKAGE)


def base64_encode(data: str) -> str:
    return b64encode(data).decode()


def get_project_root_path() -> str:
    return Path(os.path.dirname(os.path.abspath(__file__))).parent


def get_json_template_path(name: str) -> str:
    dir_name = '{}/includes/json_template/{}'.format(get_project_root_path(), name)
    return dir_name


def get_instrumentation_code_path(name: str) -> str:
    dir_name = '{}/src/instrumentation/payloads/{}'.format(get_project_root_path(), name)
    return dir_name


def init_actions_list_for_task(device_common_id: str, task: Task):
    actions_file_path = get_api_actions_file_path(task, device_common_id)

    template_path = get_json_template_path(ACTIONS_TEMPLATE_FILE_PATH)
    tmp_actions = read_json_file(template_path)
    tmp_actions[task.get_service()] = tmp_actions.pop('SERVICE')
    tmp_actions[task.get_service()][task.get_api()] = tmp_actions[task.get_service()].pop('API')

    write_json_file(actions_file_path, tmp_actions)

    return tmp_actions


def get_specific_out_dir(name: str) -> str:
    dir_name = '{}/out/{}'.format(get_project_root_path(), name)
    if not dir_exists(dir_name):
        create_dir(dir_name)
    return dir_name


def get_app_info(package_name: str) -> (str, str):
    return "{}/res/apks/{}.apk".format(get_project_root_path(), package_name)


def get_frida_server_dir() -> (str, str):
    return "{}/{}".format(get_project_root_path(), FRIDA_SERVER)


def get_device_content_provider_lists_path(common_id: str) -> str:
    dir_name = get_specific_out_dir(CONTENT_PROVIDER_LISTS)
    return '{}/{}.json'.format(dir_name, common_id)


def get_device_broadcast_lists_path(common_id: str) -> str:
    dir_name = get_specific_out_dir(BROADCAST_LISTS)
    return '{}/{}.json'.format(dir_name, common_id)


def get_tasks_dir_path(common_id: str, task_type: str) -> str:
    dir_name = get_specific_out_dir(TASKS)
    return '{}/{}/{}'.format(dir_name, common_id, task_type)


def get_service_process_map_file(common_id: str) -> str:
    dir_name = get_specific_out_dir(SERVICE_PROCESS_MAP_LISTS)
    return '{}/{}.json'.format(dir_name, common_id)


def get_local_api_lists_path(common_id: str) -> str:
    dir_name = get_specific_out_dir(API_LISTS)
    return '{}/{}.json'.format(dir_name, common_id)


def get_formatted_local_api_lists_path(common_id: str) -> str:
    dir_name = get_specific_out_dir(API_LISTS)
    return '{}/{}_formatted.json'.format(dir_name, common_id)


def file_exists(path: str) -> bool:
    return os.path.isfile(path)


def dir_exists(path: str) -> bool:
    return os.path.isdir(path)


def remove_file(path: str):
    if file_exists(path):
        os.remove(path)


def create_dir(path: str):
    os.makedirs(path, exist_ok=True)


def sha256sum(file_path):
    h = hashlib.sha256()
    b = bytearray(128*1024)
    mv = memoryview(b)
    with open(file_path, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


def read_file(path: str) -> (bool, str):
    try:
        if not file_exists(path):
            raise FileNotFoundError

        file = open(path, 'r')
        content = file.read()
        file.close()
        return True, content
    except Exception as e:
        return False, str(e)


def read_json_file(path: str) -> (bool, dict):
    success, data = read_file(path)
    if success:
        try:
            return json.loads(data)
        except Exception as e:
            raise e
            print(path)
    else:
        return None


def write_file(path: str, content: Any) -> (bool, str):
    try:
        file = open(path, 'wb+')
        file.write(content)
        file.close()
        return True, None
    except Exception as e:
        return False, str(e)


def write_json_file(path: str, json_content: Any) -> (bool, str):
    try:
        file = open(path, 'w+')
        str_content = str(json.dumps(json_content, indent=2))
        file.write(str_content)
        file.close()
        return True, None
    except Exception as e:
        return False, str(e)


def map_abi_to_architecture(abi: str) -> str:
    if abi == ABI_ARM_V7A:
        return ARM
    elif abi == ABI_ARM_64_V8A:
        return ARM64
    elif abi == ABI_X86:
        return X86
    elif abi == ABI_X86_64:
        return X86_64

    return UNKNOWN_CPU_ARCH


# see https://stackoverflow.com/a/3368991
def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def hash_obj(obj):
    return hashlib.md5(json.dumps(obj, sort_keys=True).encode('utf-8')).hexdigest()


def object_exists(obj, target_list):
    obj_hash = hash_obj(obj)
    exists = False
    for o in target_list:
        if obj_hash == hash_obj(o):
            exists = True
            break
    return exists


def add_if_unique(obj, target_list):
    exists = object_exists(obj, target_list)
    if not exists:
        target_list.append(obj)
    return target_list


def get_frida_server(abi: str) -> Any:
    # Translate abi to cpu architecture
    arch = map_abi_to_architecture(abi)

    # Prepare paths
    frida_server_name = FRIDA_SERVER_RAW_NAME.format(FRIDA_SERVER_VERSION, arch)
    download_dir = get_frida_server_dir()
    frida_server_full_path = os.path.join(download_dir, frida_server_name)
    frida_server_full_path_extracted = frida_server_full_path[:-3]

    # If the binary found, return its path!
    if file_exists(frida_server_full_path_extracted):
        return frida_server_full_path_extracted

    # If the archived file is not there, download it!
    if not file_exists(frida_server_full_path):
        url = '{}/{}'.format(FRIDA_RELEASES_URL, frida_server_name)
        wget.download(url, out=download_dir)

    # If the binary is not there, but the archived file is there, extract it!
    if file_exists(frida_server_full_path) and not file_exists(frida_server_full_path_extracted):
        data = lzma.open(frida_server_full_path).read()
        write_file(frida_server_full_path_extracted, data)
        remove_file(frida_server_full_path)
        return frida_server_full_path_extracted

    # If none of the above happened, fail!
    return None


# @TODO: change name and refactor
def change_api_format(params_raw: str) -> list:
    parameters_list = []
    search_result = re.findall("L(.+?);", params_raw)
    if len(search_result) > 0:
        for i in range(len(search_result)):
            index = params_raw.index(search_result[i])
            before_char = params_raw[index - 2]
            search_result[i] = "L{};".format(search_result[i])
            if before_char == "[":
                search_result[i] = "[{}".format(search_result[i])
            params_raw = params_raw.replace(search_result[i], "_", 1)

    for j in range(len(params_raw)):
        if params_raw[j] == "[":
            parameters_list.append("[{}".format(params_raw[j + 1]))
        elif params_raw[j] == "_":
            parameters_list.append(search_result[0][1:-1].replace("/", "."))
            search_result = search_result[1:]
        else:
            parameters_list.append("{}".format(params_raw[j]))

    for i in range(len(parameters_list)):
        if parameters_list[i].startswith("L") or parameters_list[i].startswith("["):
            parameters_list[i] = "{}[]".format(parameters_list[i][1:])

    # This is a workaround for a bug above! Please @TODO fix
    final_list = []
    skip_next = False
    for parameter in parameters_list:
        if not skip_next:
            final_list.append(parameter)
        if parameter in ['I[]', 'B[]', 'J[]', 'F[]']:
            skip_next = True
        else:
            skip_next = False

    return final_list


# @TODO: refactor this
def format_api_lists(file_path: str) -> (bool, str):
    formatted_apis = {}
    services = read_json_file(file_path)
    for service in services:
        if service == "whoami":
            formatted_apis[service] = services[service]
            continue

        if service not in formatted_apis:
            formatted_apis[service] = []

        for api in services[service]:
            params_raw = re.findall(".*(?<=\()(.*)(?=\))", api)[0]
            parameters = ""
            if params_raw != "":
                parameters_list = change_api_format(params_raw)
                parameters = ",".join(parameters_list)

            name = api.split("(")[0]
            return_raw = api.split(')')[1]
            if return_raw:
                temp_list = change_api_format(return_raw)
                return_type = "" if len(temp_list) == 0 else temp_list[0]

            formatted_apis[service].append("{}|{}|{}|{}|".format(service, name, parameters, return_type))

    file_path = file_path.replace(".json", API_LIST_FILE_NAME_SUFFIX)
    return write_json_file(file_path, formatted_apis)


def create_api_tasks_files(device_common_id: str):
    uids = UIDS_TO_FUZZ

    root_tasks = get_tasks_dir_path(device_common_id, APIS)
    if not dir_exists(root_tasks):
        create_dir(root_tasks)

    api_list = get_formatted_local_api_lists_path(device_common_id)
    services = read_json_file(api_list)

    task_dir_name = get_tasks_dir_path(device_common_id, APIS)
    if not dir_exists(task_dir_name):
        create_dir(task_dir_name)

    stats = copy.deepcopy(STATS_GENERIC)

    parameters_generator = ParametersGenerator()

    for service in services:
        if service == "whoami":
            continue

        stats['services_count'] = stats['services_count'] + 1

        for api in services[service]:
            if service not in stats['services']:
                stats['apis'] = stats['apis'] + len(services[service])
                stats['remaining'] = stats['remaining'] + len(services[service])

                stats['services'][service] = copy.deepcopy(STATS_SERVICE_GENERIC)
                stats['services'][service]['apis'] = len(services[service])
                stats['services'][service]['remaining'] = len(services[service])

            if api not in stats['services'][service]['remaining_list']:
                stats['services'][service]['remaining_list'].append(api)

            api_name = get_api_name(api)
            file_name = "{}.{}".format(service, api_name)
            setup_file_dir_path = os.path.join(root_tasks, file_name)
            if not dir_exists(setup_file_dir_path):
                create_dir(setup_file_dir_path)

            # Don't use get_task_config_file_path as it will create the target file.
            setup_file_file_path = os.path.join(root_tasks, file_name, CONFIG_FILE_NAME)
            if not file_exists(setup_file_file_path):
                parameters = get_parameters(api).split(",")
                generated_parameters = parameters_generator.generate_primitive_types(parameters)
                prepared_parameters = {}

                for p in generated_parameters:
                    prepared_parameters[hash_obj(p)] = p

                data = {
                    'api': api,
                    'parameters_count': len(generated_parameters),
                    'parameters': prepared_parameters,
                    'parameters_done': {},
                    'uids': uids,
                    'uids_done': [],
                    'classes': [],
                    'phase_name': None,
                    'errors': {},
                    'pids': [],
                    'pids_done': []
                }

                write_json_file(setup_file_file_path, data)

    stats_file_path = os.path.join(task_dir_name, STATS_FILE_NAME)
    if not file_exists(stats_file_path):
        write_json_file(stats_file_path, stats)


def get_api_fuzzing_file_path(task: Task, device_common_id: str, file_name: str, default_content: Any):
    root_tasks = get_tasks_dir_path(device_common_id, APIS)

    api_name = task.get_api()
    service_api_name = "{}.{}".format(task.get_service(), api_name)

    if task.get_task_type() == APIS:
        actions_file_path = os.path.join(root_tasks, service_api_name, file_name)
    else:
        raise NotImplemented

    if not file_exists(actions_file_path):
        write_json_file(actions_file_path, default_content)

    return actions_file_path


def get_task_config(task: Task, device_common_id: str) -> dict:
    config_file_path = get_task_config_file_path(task, device_common_id)
    config = read_json_file(config_file_path)

    if 'not_instrumented' not in config['errors']:
        config['errors']['not_instrumented'] = 0

    if 'historical_not_instrumented' not in config['errors']:
        config['errors']['historical_not_instrumented'] = 0

    if 'service_not_invoked' not in config['errors']:
        config['errors']['service_not_invoked'] = 0

    if 'historical_service_not_invoked' not in config['errors']:
        config['errors']['historical_service_not_invoked'] = 0

    if 'no_traces' not in config['errors']:
        config['errors']['no_traces'] = 0

    if 'historical_no_traces' not in config['errors']:
        config['errors']['historical_no_traces'] = 0

    return config


def persist_task_config(task: Task, device_common_id: str, config: dict):
    config_file_path = get_task_config_file_path(task, device_common_id)
    write_json_file(config_file_path, config)


def get_actions_count(task: Task, device_common_id: str) -> (dict, bool):
    actions_file_path = get_api_actions_file_path(task, device_common_id)
    actions = read_json_file(actions_file_path)
    return len(actions[task.get_service()][task.get_api()]['ordered_iterations'])


def get_last_processed_action(task: Task, device_common_id: str) -> dict:
    actions_file_path = get_api_actions_file_path(task, device_common_id)
    actions = read_json_file(actions_file_path)

    if task.get_service() not in actions or task.get_api() not in actions[task.get_service()]:
        actions = init_actions_list_for_task(device_common_id, task)

    ordered_iterations = actions[task.get_service()][task.get_api()]['ordered_iterations']

    return None if len(ordered_iterations) == 0 else ordered_iterations[-1]


def stacktrace_was_reported_before(task: Task, device_common_id: str) -> (dict, bool):
    actions_file_path = get_api_actions_file_path(task, device_common_id)
    actions = read_json_file(actions_file_path)

    stacktrace_reported = False
    invocation_succeeded = False

    ordered_iterations = actions[task.get_service()][task.get_api()]['ordered_iterations']
    for iteration in ordered_iterations:
        if 'stacktrace' in iteration and len(iteration['stacktrace']) > 0:
            stacktrace_reported = True
        if 'execution_outcome' in iteration and iteration['execution_outcome']['returns']:
            invocation_succeeded = True

    return stacktrace_reported, invocation_succeeded


def is_repeated_action(task, device_common_id, data: dict, repetition: int) -> bool:
    actions_file_path = get_api_actions_file_path(task, device_common_id)
    actions = read_json_file(actions_file_path)

    if task.get_service() not in actions or task.get_api() not in actions[task.get_service()]:
        actions = init_actions_list_for_task(device_common_id, task)

    ordered_iterations = actions[task.get_service()][task.get_api()]['ordered_iterations']

    try:
        i = 2
        while repetition > 0:
            if 'deferred_action' in ordered_iterations[-1 * i] or 'skip' in ordered_iterations[-1 * i] or \
                    hash_obj(data) != hash_obj(ordered_iterations[-1 * i]['data']):
                return False
            repetition = repetition - 1
            i = i + 1

        return True
    except:
        return False


def get_api_actions_file_path(task: Task, device_common_id: str):
    return get_api_fuzzing_file_path(task, device_common_id, API_ACTIONS_FILE_NAME, {})


def get_deferred_actions_file_path(task: Task, device_common_id: str):
    return get_api_fuzzing_file_path(task, device_common_id, API_DEFERRED_ACTIONS_FILE_NAME, [])


def get_deferred_actions(task: Task, device_common_id: str):
    path = get_api_fuzzing_file_path(task, device_common_id, API_DEFERRED_ACTIONS_FILE_NAME, [])
    return read_json_file(path)


def exists_deferred_actions_for_parameters_hash(task: Task, device_common_id: str, parameters_hash: str) -> bool:
    deferred_actions = get_deferred_actions(task, device_common_id)
    for da in deferred_actions:
        if 'processed' not in da and 'data' in da and da['data']['parameters_hash'] == parameters_hash and parameters_hash:
            return True

    return False


def persist_deferred_actions(task: Task, device_common_id: str, deferred_actions: list):
    path = get_api_fuzzing_file_path(task, device_common_id, API_DEFERRED_ACTIONS_FILE_NAME, [])
    return write_json_file(path, deferred_actions)


def get_task_config_file_path(task: Task, device_common_id: str):
    return get_api_fuzzing_file_path(task, device_common_id, CONFIG_FILE_NAME, {})


def get_ordered_action_template():
    template_path = get_json_template_path(ORDERED_ACTION_TEMPLATE_FILE_NAME)
    ordered_action = read_json_file(template_path)
    return ordered_action


def get_adb_path():
    return os.path.join(get_project_root_path(), "res/android-platform-tools/adb")


def pull_api_task_recursively(device_common_id: str, selected_service_api: str = None, selected_service: str = None):
    stats = get_stats(device_common_id)

    if selected_service:
        targeted_service = selected_service
        targeted_api = ""
    elif selected_service_api:
        tokens = selected_service_api.split(":")
        targeted_service = tokens[0]
        targeted_api = tokens[1]
    else:
        targeted_service = ""
        targeted_api = ""

    for service in stats['services']:
        if targeted_service:
            s = stats['services'][targeted_service]
        else:
            s = stats['services'][service]

        api = ""
        if len(s['remaining_list']) > 0:
            if targeted_api:
                index = 0
                for a in s['remaining_list']:
                    if '|{}|'.format(targeted_api) in a:
                        api = a
                        del s['remaining_list'][index]
                        break
                    index = index + 1
            else:
                api = s['remaining_list'][0]
                del s['remaining_list'][0]

            if api:
                s['selected_list'].append(api)
            else:
                return ""

            stats['pending'] = stats['pending'] + 1
            stats['remaining'] = stats['remaining'] - 1

            s['pending'] = s['pending'] + 1
            s['remaining'] = s['remaining'] - 1

            persist_stats(device_common_id, stats)

            return api

    return ""


def enqueue_api_task(device_common_id, task: Task):
    stats = get_stats(device_common_id)

    for service in stats['services']:
        s = stats['services'][service]
        if task.get_api_raw() in s['selected_list']:
            s['selected_list'].remove(task.get_api_raw())
            s['remaining_list'].insert(0, task.get_api_raw())

            stats['pending'] = stats['pending'] - 1
            stats['remaining'] = stats['remaining'] + 1

            s['pending'] = s['pending'] - 1
            s['remaining'] = s['remaining'] + 1

            persist_stats(device_common_id, stats)

            return True
    return False


def finish_api_task(device_common_id, task: Task):
    stats = get_stats(device_common_id)

    for service in stats['services']:
        s = stats['services'][service]
        if task.get_api_raw() in s['selected_list']:
            s['selected_list'].remove(task.get_api_raw())
            s['done_list'].append(task.get_api_raw())

            stats['pending'] = stats['pending'] - 1
            stats['done'] = stats['done'] + 1

            s['pending'] = s['pending'] - 1
            s['done'] = s['done'] + 1

            persist_stats(device_common_id, stats)

            return True
    return False
