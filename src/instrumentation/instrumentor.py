from .instrumentation_config import InstrumentationConfig
from models.task import Task
from models.device import Device

from utils import helpers
from utils.log import Logger
from src.analyze.analyzer import Analyzer

from includes.constants import FUZZER_APP_PKG_NAME, INVOKER_SERVICE, FIRST_USER_ID_SWITCH_PROFILE, FIRST_USER_ID, \
    SYSTEM_SERVER, SERVICE_MANAGER, INSTRUMENT_SERVICE_PROCESS_MAPPER_FILE, INSTRUMENT_PERMISSION_MAPPER_FILE, \
    INSTRUMENT_PERMISSION_MAPPER_REPLACE_VALUE, REPEAT_SAME_PARAMETERS_MAX, ACTION_CONTINUE, ACTION_END, \
    ACTION_CHANGE_PARAMETERS, ACTION_START, ACTION_CHANGE_UID, ACTION_EXECUTE_DEFERRED, ACTION_CHANGE_PID, \
    HASH_PLACEHOLDER

import frida
import time
import copy
import json
from typing import Any


class Instrumentor:
    duplicate_messages_count = 0
    previous_message_hash = None


    """
    ' The code of this function "construct_service_process_map" is copied and adapted
    '   from https://github.com/dessertlab/fantastic_beasts project
    """
    def construct_service_process_map(self) -> []:
        service_process_map_file_path = helpers.get_service_process_map_file(self.device.get_common_id())

        if helpers.file_exists(service_process_map_file_path):
            return

        current_name = ''
        current_pid = ''
        selinux_type = ''
        service_process_map = []
        service_process_map_simple = []
        self.collecting_results_began = False
        self.wait_until = time.time()

        def process_payload(payload):
            global current_name
            global current_pid
            global selinux_type

            if 'name' in payload['key']:
                current_name = payload['value']
            elif 'pid' in payload['key']:
                current_pid = payload['value']
            elif 'selinux_type' in payload['key']:
                selinux_type = payload['value']
            elif 'perm' in payload['key']:
                if 'add' in payload['value']:
                    self.collecting_results_began = True
                    self.wait_until = time.time() + 120

                    try:
                        current_pid = int(current_pid)
                    except:
                        current_pid = -1

                    try:
                        selinux_type
                    except:
                        selinux_type = ''

                    entry = {
                        'service': current_name,
                        'host': self.device.get_package_name_by_pid(int(current_pid))['name']
                    }

                    if not entry['host']:
                        names = self.device.get_process_name_by_selinux_type(selinux_type)
                        entry['host'] = ','.join(names)

                    if not entry['host']:
                        entry['selinux_types'] = selinux_type

                    if entry['service'] and current_name not in service_process_map_simple:
                        service_process_map.append(entry)
                        service_process_map_simple.append(current_name)

                    current_name = ''
                    current_pid = ''
                    selinux_type = ''

        def on_message(message, data):
            if 'send' in message['type']:
                process_payload(message['payload'])

        js_payload_path = helpers.get_instrumentation_code_path(INSTRUMENT_SERVICE_PROCESS_MAPPER_FILE)
        success, js_code = helpers.read_file(js_payload_path)
        if not success:
            return []

        device = None
        device_id = self.device.get_device_id()
        while device is None:
            try:
                device = frida.get_device(device_id, 10)
            except frida.TimedOutError:
                pass
        process = frida.get_device(device_id, 10).attach(SERVICE_MANAGER)
        process.enable_jit()
        script = process.create_script(js_code)
        script.on('message', on_message)
        script.load()

        self.device.kill_process('zygote', True)

        self.logger.ilog("Waiting for all binder services to register themselves!")
        while True:
            if self.collecting_results_began:
                if time.time() >= self.wait_until:
                    break
                else:
                    time.sleep(1)
            else:
                time.sleep(1)
        self.logger.ilog("Done collecting results for service-process maps")

        services = self.device.get_binder_services_list()
        for service in services:
            if service not in service_process_map_simple:
                service_process_map.append({
                    'service': service,
                    'host': ''
                })

        if not helpers.file_exists(service_process_map_file_path):
            helpers.write_json_file(service_process_map_file_path, service_process_map)
        else:
            map = helpers.read_json_file(service_process_map_file_path)
            my_specified_hosts = 0
            current_specified_hosts = 0
            for service in map:
                if service['host']:
                    current_specified_hosts = current_specified_hosts + 1
            for service in service_process_map:
                if service['host']:
                    my_specified_hosts = my_specified_hosts + 1
            if my_specified_hosts > current_specified_hosts:
                helpers.write_json_file(service_process_map_file_path, service_process_map)

        process.detach()

        return service_process_map

    def get_instrumentation_setup(self, task: Task, instrumentation_config: InstrumentationConfig):
        setup = {}

        fake_uid = instrumentation_config.get_fake_uid()
        fake_pid = instrumentation_config.get_fake_pid()

        setup['method'] = task.get_api()
        setup['service'] = task.get_service()
        setup['uid'] = instrumentation_config.get_real_uid()
        setup['pid'] = instrumentation_config.get_real_pid()
        setup['profile'] = instrumentation_config.get_real_profile()
        setup['fake_uid'] = fake_uid
        setup['fake_pid'] = fake_pid
        setup['fake_pid_name'] = instrumentation_config.get_fake_pid_name()
        setup['fake_profile'] = instrumentation_config.get_fake_profile()
        setup['permissions'] = instrumentation_config.get_granted_permissions()
        setup['user_restrictions'] = instrumentation_config.get_user_restrictions()
        setup['app_ops'] = instrumentation_config.get_granted_app_ops_permissions()
        setup['fake_uid_pkg_name'] = self.device.get_package_name_by_uid(fake_uid)['name']
        setup['fuzzer_pkg_name'] = FUZZER_APP_PKG_NAME
        setup['parameters'] = instrumentation_config.get_fuzzed_parameters()
        setup['parameters_hash'] = instrumentation_config.get_fuzzed_parameters_hash()
        setup['instrumented_classes'] = [] if self.device.is_su_c_supported() else instrumentation_config.get_classes_to_instrument()
        #setup['instrumented_classes'] = instrumentation_config.get_classes_to_instrument()
        setup['switch_profile'] = instrumentation_config.get_force_switch_profile()
        setup['ignored_permissions'] = instrumentation_config.get_ignored_permissions()
        setup['is_hardware'] = self.device.is_su_c_supported()

        return setup

    def get_next_parameters(self, task: Task, fuzzed_uid: Any, parameter_hash: str = None) -> (list, str):
        config = helpers.get_task_config(task, self.device.get_common_id())
        fuzzed_uid = fuzzed_uid if fuzzed_uid in config['uids'] else None

        params_hash = None

        if not parameter_hash:
            for p_h in config['parameters']:
                formatted_hash = "{}:{}".format(fuzzed_uid, p_h)
                if formatted_hash not in config['parameters_done'] or \
                        (formatted_hash in config['parameters_done'] and
                         config['parameters_done'][formatted_hash] < REPEAT_SAME_PARAMETERS_MAX):
                    params_hash = p_h
                    break
        else:
            params_hash = parameter_hash

        ret = {
            'parameters': [],
            'hash': HASH_PLACEHOLDER,
            'parameterized': config['parameters_count'] > 0
        }

        if params_hash and params_hash != HASH_PLACEHOLDER:
            ret['parameters'] = config['parameters'][params_hash]
            ret['hash'] = params_hash

        return ret

    def set_deferred_action_for_execution(self, task: Task, fuzzed_uid: int) -> Any:
        path = helpers.get_deferred_actions_file_path(task, self.device.get_common_id())
        deferred_actions = helpers.read_json_file(path)
        uid_resolved = (fuzzed_uid if fuzzed_uid else self.device.get_app_uid(FUZZER_APP_PKG_NAME))
        for deferred_action in deferred_actions:
            if 'processed' not in deferred_action and deferred_action['data']['uid'] in [uid_resolved, fuzzed_uid]:
                # Get the deferred action
                deferred_action['deferred_action'] = True
                actions_path = helpers.get_api_actions_file_path(task, self.device.get_common_id())
                actions = helpers.read_json_file(actions_path)
                actions[task.get_service()][task.get_api()]['ordered_iterations'].append(deferred_action)
                helpers.write_json_file(actions_path, actions)

                # Flag current action as processed!
                deferred_action['processed'] = True
                helpers.write_json_file(path, deferred_actions)

                parameters_sets = [
                    "{}:{}".format(str(uid_resolved), deferred_action['data']['parameters_hash']),
                    "{}:{}".format(str(fuzzed_uid), deferred_action['data']['parameters_hash'])
                ]

                # Reset parameters count
                config = helpers.get_task_config(task, self.device.get_common_id())
                for parameter in config['parameters_done']:
                    if parameter in parameters_sets:
                        config['parameters_done'][parameter] = 0
                helpers.persist_task_config(task, self.device.get_common_id(), config)

                return deferred_action
        return None

    def set_action_for_uid(self, task: Task, fuzzed_uid: Any, process_name: str = None) -> dict:
        ordered_action = helpers.get_ordered_action_template()
        ordered_action['data']['uid'] = fuzzed_uid

        if process_name:
            ordered_action['data']['pid'] = process_name

        ordered_action['skip'] = True

        path = helpers.get_api_actions_file_path(task, self.device.get_common_id())
        actions = helpers.read_json_file(path)
        actions[task.get_service()][task.get_api()]['ordered_iterations'].append(ordered_action)

        helpers.write_json_file(path, actions)

        return ordered_action

    def get_next_uid_to_fuzz(self, task: Task) -> (bool, int):
        config = helpers.get_task_config(task, self.device.get_common_id())

        target_uid = None
        found = False
        for uid in config['uids']:
            if uid not in config['uids_done']:
                target_uid = uid
                found = True
                break

        return found, target_uid

    def flag_uid_complete(self, task: Task, fuzzed_uid: Any) -> (bool, int):
        config = helpers.get_task_config(task, self.device.get_common_id())
        config['uids_done'].append(fuzzed_uid)
        helpers.persist_task_config(task, self.device.get_common_id(), config)

        return self.get_next_uid_to_fuzz(task)

    def prepare_next_step(self, task: Task) -> (str, Any):
        last_action = helpers.get_last_processed_action(task, self.device.get_common_id())
        if not last_action:
            return ACTION_START, None

        is_repeated = 'data' in last_action and \
                      helpers.is_repeated_action(task, self.device.get_common_id(), last_action['data'], 1)

        """
        " ACTION: ACTION_CONTINUE
        " Nothing changed, i.e., has to repeat operation at least one more time!
        """
        if not is_repeated:
            return ACTION_CONTINUE, None

        config = helpers.get_task_config(task, self.device.get_common_id())

        fuzzed_uid = None
        if last_action and 'data' in last_action:
            # In case None is resolved to app's UID which is not included in the uids list
            fuzzed_uid = last_action['data']['uid'] if last_action['data']['uid'] in config['uids'] else None

        parameters_info = self.get_next_parameters(task, fuzzed_uid)

        """
        " ACTION: ACTION_EXECUTE_DEFERRED
        " One deferred action is found for the same parameters' set
        """
        deferred_action_exists = helpers.\
            exists_deferred_actions_for_parameters_hash(task, self.device.get_common_id(), parameters_info['hash'])
        if config['phase_name'] == ACTION_EXECUTE_DEFERRED or deferred_action_exists:
            deferred_action = self.set_deferred_action_for_execution(task, fuzzed_uid)
            if deferred_action:
                return ACTION_EXECUTE_DEFERRED, parameters_info

        if (len(parameters_info['parameters']) == 0 and parameters_info['parameterized']) or \
                not parameters_info['parameterized']:
            """
            " ACTION: ACTION_CHANGE_PID
            " Before trying another UID to fuzz, try to fuzz PIDs for the "None" UID
            """
            if fuzzed_uid is None and "pids" in config and len(config['pids']) > 0:
                name_hash = config['pids'][0].split(":")
                process_name = name_hash[0]
                parameters_hash = name_hash[1]

                config['parameters_done']["None:{}".format(parameters_hash)] = 0
                if "pids_done" not in config:
                    config['pids_done'] = []

                config['pids_done'].append(config['pids'][0])
                del config['pids'][0]

                helpers.persist_task_config(task, self.device.get_common_id(), config)

                self.set_action_for_uid(task, None, process_name)
                parameters_info = self.get_next_parameters(task, None, parameters_hash)
                return ACTION_CHANGE_PID, parameters_info

            """
            " ACTION: ACTION_CHANGE_UID
            " No parameters, pids, and deffered actions to fuzz, so let's try fuzzing another UID, if there is any!
            """
            new_uid_exists, new_fuzzed_uid = self.flag_uid_complete(task, fuzzed_uid)
            if new_uid_exists:
                self.set_action_for_uid(task, new_fuzzed_uid)
                return ACTION_CHANGE_UID, new_fuzzed_uid

        """
        " ACTION: ACTION_CHANGE_PARAMETERS
        " Oh! there is one parameters set to fuzz!
        """
        if len(parameters_info['parameters']) > 0:
            return ACTION_CHANGE_PARAMETERS, parameters_info

        return ACTION_END, None

    def prepare_fuzzing_file(self, task):
        name_next_action, contextual_parameter = self.prepare_next_step(task)

        if name_next_action == ACTION_END:
            return None

        self.device.unlock()
        time.sleep(2)
        self.device.start_fuzzing_app_main_activity()
        time.sleep(2)

        granted_permissions = []
        ignored_permissions = []
        user_restrictions = []
        granted_app_ops_permissions = []

        fake_uid = self.device.get_app_uid(FUZZER_APP_PKG_NAME)
        real_uid = fake_uid
        fake_profile = self.device.get_user_id(fake_uid)
        real_profile = fake_profile
        service = "{}:{}".format(FUZZER_APP_PKG_NAME, INVOKER_SERVICE)
        fake_pid = self.device.get_pid_by_process_name(service)
        fake_pid_name = service
        real_pid = fake_pid
        switch_profile = False
        parameters_info = None

        print(self.device.get_device_id(), "ACTION", name_next_action)
        if name_next_action != ACTION_CONTINUE:
            config = helpers.get_task_config(task, self.device.get_common_id())
            config['phase_name'] = name_next_action
            helpers.persist_task_config(task, self.device.get_common_id(), config)

        if name_next_action == ACTION_START:
            pass

        elif name_next_action in [ACTION_CONTINUE, ACTION_EXECUTE_DEFERRED, ACTION_CHANGE_UID, ACTION_CHANGE_PID,
                                  ACTION_CHANGE_PARAMETERS]:
            action_ = helpers.get_last_processed_action(task, self.device.get_common_id())
            last_action = action_['data']

            if name_next_action in [ACTION_CHANGE_PARAMETERS, ACTION_EXECUTE_DEFERRED, ACTION_CHANGE_PID]:
                parameters_info = contextual_parameter
            else:
                parameters_info = self.get_next_parameters(task, last_action['uid'])

            if last_action['parameters_hash'] in [HASH_PLACEHOLDER, None] or \
                    last_action['parameters_hash'] == parameters_info['hash'] or \
                    name_next_action == ACTION_CHANGE_PID:
                for perm in last_action['permissions']:
                    granted_permissions.append(perm)

                for restriction in last_action['user_restrictions']:
                    user_restrictions.append(restriction)

                for op in last_action['appOps']:
                    granted_app_ops_permissions.append(op)

                if last_action['uid'] is not None:
                    fake_uid = last_action['uid']
                    if fake_uid == FIRST_USER_ID_SWITCH_PROFILE:
                        switch_profile = True

                if last_action['userId'] is not None:
                    if last_action['uid'] is not None and last_action['uid'] >= FIRST_USER_ID:
                        fake_profile = self.device.get_user_id_of_second_profile()
                    else:
                        fake_profile = last_action['userId']

                if last_action['pid'] is not None:
                    fake_pid = self.device.get_pid_by_process_name(last_action['pid'])
                    fake_pid_name = last_action['pid']

                if "ignored_permissions" in last_action:
                    ignored_permissions = last_action['ignored_permissions']
            elif last_action:
                fake_uid = self.device.get_app_uid(FUZZER_APP_PKG_NAME) if last_action['uid'] is None else last_action['uid']

        if not parameters_info:
            uid_exists, fuzzed_uid = self.get_next_uid_to_fuzz(task)
            parameters_info = self.get_next_parameters(task, fuzzed_uid)

        config = helpers.get_task_config(task, self.device.get_common_id())
        classes_to_instrument = config['classes']

        next_parameters = parameters_info['parameters']

        # Resolve parameter's prefix!
        for i in range(len(next_parameters)):
            if next_parameters[i].startswith("INDEX:"):
                parameter_position = int(next_parameters[i].replace("INDEX:", ""))
                next_parameters[i] = next_parameters[parameter_position]

        for i in range(len(next_parameters)):
            if next_parameters[i].startswith("INT:UID:SECOND_PROFILE:"):
                app_pkg_name = next_parameters[i].replace("INT:UID:SECOND_PROFILE:", "")
                next_parameters[i] = "INT:{}".format(self.device.get_app_uid(app_pkg_name) + FIRST_USER_ID)
            elif next_parameters[i].startswith("INT:UID:"):
                app_pkg_name = next_parameters[i].replace("INT:UID:", "")
                next_parameters[i] = "INT:{}".format(self.device.get_app_uid(app_pkg_name))
            elif next_parameters[i].startswith("INT:PID:"):
                app_pkg_name = next_parameters[i].replace("INT:PID:", "")
                next_parameters[i] = "INT:{}".format(self.device.get_pid_by_process_name(app_pkg_name))
            elif next_parameters[i].startswith("S:UID:"):
                app_pkg_name = next_parameters[i].replace("S:UID:", "")
                next_parameters[i] = "S:{}".format(self.device.get_app_uid(app_pkg_name))

        instrumentation_config = InstrumentationConfig()
        instrumentation_config.set_fake_profile(fake_profile)
        instrumentation_config.set_real_profile(real_profile)
        instrumentation_config.set_fake_uid(fake_uid)
        instrumentation_config.set_real_uid(real_uid)
        instrumentation_config.set_fake_pid(fake_pid)
        instrumentation_config.set_fake_pid_name(fake_pid_name)
        instrumentation_config.set_real_pid(real_pid)
        instrumentation_config.set_granted_permissions(granted_permissions)
        instrumentation_config.set_user_restrictions(user_restrictions)
        instrumentation_config.set_granted_app_ops_permissions(granted_app_ops_permissions)
        instrumentation_config.set_classes_to_instrument(classes_to_instrument)
        instrumentation_config.set_force_switch_profile(switch_profile)
        instrumentation_config.set_fuzzed_parameters(next_parameters)
        instrumentation_config.set_fuzzed_parameters_hash(parameters_info['hash'])
        instrumentation_config.set_ignored_permissions(ignored_permissions)

        return self.get_instrumentation_setup(task, instrumentation_config)

    def instrument_and_wait(self, task: Task, setup: dict, analyzer: Analyzer):

        self.collecting_results_began = False
        self.messages_received = 0

        def on_message(msg, _data):
            if msg['type'] == "error":
                self.logger.ilog(msg['description'])
            if msg['type'] == "send":
                self.collecting_results_began = True
                if "processable" in msg['payload']:
                    self.messages_received = self.messages_received + 1
                    print(self.device.get_device_id(), msg['payload']['processable']['call_ret'])
                    analyzer.enqueue_result(msg['payload']['processable'])
            if msg['type'] != "send" and msg['type'] != "error":
                self.logger.ilog(msg)

            try:
                if helpers.hash_obj(msg['payload']['processable']) == self.previous_message_hash:
                    self.duplicate_messages_count = self.duplicate_messages_count + 1
                else:
                    self.duplicate_messages_count = 0
                    self.previous_message_hash = helpers.hash_obj(msg['payload']['processable'])
            except:
                print(msg)

            if self.duplicate_messages_count < 3:
                self.wait_until = time.time() + 5

        try:
            fuzzing_service = "{}:{}".format(FUZZER_APP_PKG_NAME, INVOKER_SERVICE)

            to_instrument_by_name = [
                SYSTEM_SERVER
            ]
            #fuzzing_service
            to_instrument_by_name_and_pid = []
            to_instrument_by_pid = []

            service_process_map_file_path = helpers.get_service_process_map_file(self.device.get_common_id())
            service_process_map = helpers.read_json_file(service_process_map_file_path)

            target_process = ""
            for _map in service_process_map:
                if _map['service'] == setup['service']:
                    target_process = _map['host']
                    break

            if target_process == "":
                self.logger.elog("couldn't find the host process for the service {}! "
                                 "This affects the quality of results. Please fix!".format(setup['service']))
                target_process = SYSTEM_SERVER

            if target_process != "" and target_process not in to_instrument_by_name:
                to_instrument_by_name.append(target_process)

            if setup['service'] == 'vold' and 'vold' not in to_instrument_by_name:
                to_instrument_by_name.append('vold')
            elif setup['service'] == 'installd' and 'installd' not in to_instrument_by_name:
                to_instrument_by_name.append('installd')
            elif setup['service'] == 'media.camera' and 'cameraserver' not in to_instrument_by_name:
                to_instrument_by_name.append('cameraserver')
            elif setup['service'] == 'incident' and 'incidentd' not in to_instrument_by_name:
                to_instrument_by_name.append('incidentd')
            elif setup['service'] == 'android.security.keystore' and 'keystore' not in to_instrument_by_name:
                to_instrument_by_name.append('keystore')
            elif setup['service'] == 'stats' and 'statsd' not in to_instrument_by_name:
                to_instrument_by_name.append('statsd')

            for process_name in to_instrument_by_name:
                if process_name == fuzzing_service:
                    self.device.start_fuzzing_app_main_activity(setup['fake_profile'])
                    time.sleep(3)

                print(self.device.get_frida_process_ids(process_name))

                for pid in self.device.get_frida_process_ids(process_name):
                    to_instrument_by_name_and_pid.append("{}:::{}".format(process_name, pid))
                    to_instrument_by_pid.append(pid)
                    print(pid, process_name)

            print(self.device.get_device_id(), to_instrument_by_name, to_instrument_by_pid)

            config = helpers.get_task_config(task, self.device.get_common_id())
            if 'not_instrumented' not in config['errors']:
                config['errors']['not_instrumented'] = 0
            if 'historical_not_instrumented' not in config['errors']:
                config['errors']['historical_not_instrumented'] = 0

            if len(to_instrument_by_name) != len(to_instrument_by_pid):
                config['errors']['not_instrumented'] = config['errors']['not_instrumented'] + 1
                config['errors']['historical_not_instrumented'] = config['errors']['historical_not_instrumented'] + 1
                helpers.persist_task_config(task, self.device.get_common_id(), config)
                self.logger.elog("Not all processes can be instrumented!")
                return False, to_instrument_by_pid
            else:
                config['errors']['not_instrumented'] = 0
                helpers.persist_task_config(task, self.device.get_common_id(), config)

            for name_pid in to_instrument_by_name_and_pid:
                try:
                    js_payload_path = helpers.get_instrumentation_code_path(INSTRUMENT_PERMISSION_MAPPER_FILE)
                    success, source = helpers.read_file(js_payload_path)
                    if not success:
                        return False, to_instrument_by_pid

                    process_name = name_pid.split(":::")[0]
                    process_id = int(name_pid.split(":::")[1])

                    setup['being_instrumented'] = process_name
                    new_source = source.replace(INSTRUMENT_PERMISSION_MAPPER_REPLACE_VALUE,
                                                "var setup = {}".format(json.dumps(setup)))

                    frida_device = None
                    device_id = self.device.get_device_id()
                    while frida_device is None:
                        try:
                            frida_device = frida.get_device(device_id, 10)
                        except frida.TimedOutError:
                            pass
                    process = frida.get_device(device_id, 10).attach(process_id)
                    process.enable_jit()
                    #print(new_source)
                    script = process.create_script(new_source)
                    script.on('message', on_message)
                    script.load()
                except Exception as e:
                    self.logger.exception(__file__, self.instrument_and_wait, e)

            config = helpers.get_task_config(task, self.device.get_common_id())
            if 'service_not_invoked' not in config['errors']:
                config['errors']['service_not_invoked'] = 0
            if 'historical_service_not_invoked' not in config['errors']:
                config['errors']['historical_service_not_invoked'] = 0

            #print(self.device.get_device_id(), "Waiting 3 seconds before calling the fuzzing service.")
            #time.sleep(3)

            success = self.device.invoke_service(setup['profile'])
            if not success:
                config['errors']['service_not_invoked'] = config['errors']['service_not_invoked'] + 1
                config['errors']['historical_service_not_invoked'] = config['errors']['historical_service_not_invoked'] + 1
                helpers.persist_task_config(task, self.device.get_common_id(), config)
                self.logger.elog("Couldn't invoke the fuzzing service!")
                return False, to_instrument_by_pid
            else:
                config['errors']['service_not_invoked'] = 0
                helpers.persist_task_config(task, self.device.get_common_id(), config)

            self.logger.ilog("Waiting incoming messages!")
            end_if_no_results_at = time.time() + 10
            while True:
                if self.collecting_results_began:
                    if self.messages_received > 100:
                        print(self.device.get_device_id(), "sleep 5s more")
                        time.sleep(5)
                        break
                    elif time.time() >= self.wait_until:
                        break
                    else:
                        time.sleep(1)
                else:
                    if time.time() >= end_if_no_results_at:
                        break
                    time.sleep(1)
            self.logger.ilog("Done waiting for incoming messages")

            return True, to_instrument_by_pid

        except Exception as e:
            self.device.reboot(wait=True)
            self.logger.exception(__file__, self.instrument_and_wait, e)
            return False, []

    def __init__(self, device: Device):
        self.device = device
        self.logger = Logger(self.device)
        self.collecting_results_began = False
        self.wait_until = time.time()
        self.messages_received = 0
