import queue
from models.device import Device
from includes.constants import FIRST_USER_ID, FIRST_USER_ID_SWITCH_PROFILE, FUZZER_APP_PKG_NAME, ACTION_CHANGE_PID

import copy
from utils import helpers
import re
from models.task import Task
from itertools import repeat
import hashlib
import uuid


class Analyzer:
    ordered_action = helpers.get_ordered_action_template()
    action_template = ordered_action['data']

    CONTEXT_IMPL_CLASS = "android.app.ContextImpl"
    PACKAGE_MANAGER_SERVICE_CLASS = "com.android.server.pm.PackageManagerService"
    USER_HANDLE_CLASS = "android.os.UserHandle"

    CHECK_UID_PERMISSION = "checkUidPermission"
    CHECK_PERMISSION = "checkPermission"
    CHECK_CALLING_PERMISSION = "checkCallingPermission"
    ENFORCE_PERMISSION = "enforcePermission"
    ENFORCE = "enforce"
    ENFORCE_CALLING_OR_SELF_PERMISSION = "enforceCallingOrSelfPermission"
    ENFORCE_CALLING_PERMISSION = "enforceCallingPermission"
    CHECK_CALLING_OR_SELF_PERMISSION = "checkCallingOrSelfPermission"
    CHECK_SELF_PERMISSION = "checkSelfPermission"

    IS_ISOLATED = "isIsolated"
    HAS_USER_RESTRICTION = "hasUserRestriction"
    NOTE_OP = "noteOp"
    CHECK_OP = "checkOp"
    START_OP = "startOp"
    NOTE_OPERATION = "noteOperation"
    CHECK_OPERATION = "checkOperation"
    START_OPERATION = "startOperation"

    def get_method_parameters(self, return_exp):
        try:
            return re.search(".*(?<=\()(.*)(?=\))", return_exp['call_ret'])[1].split(", ")
        except:
            return None

    def has_parameter_of(self, return_exp, param):
        parameters = self.get_method_parameters(return_exp)
        if parameters:
            for p in parameters:
                if p == str(param):
                    return True
        return False

    def get_parameter_at_index(self, return_exp, index):
        parameters = self.get_method_parameters(return_exp)
        if index < len(parameters):
            return parameters[index]
        return None

    def get_return_value(self, return_exp):
        return return_exp['call_ret'].split("= ")[1]

    def method_returns(self, return_exp, ret):
        return "= {}".format(ret) in return_exp['call_ret']

    def is_method(self, return_exp, method):
        return "{}(".format(method) in return_exp['call_ret']

    def is_method_and_returns(self, return_exp, method, ret):
        return self.is_method(return_exp, method) and self.method_returns(return_exp, ret)

    def is_method_from_class(self, return_exp, method, class_name):
        try:
            invoked_from = return_exp['callstack'].split("\n")[3]
            return class_name in invoked_from and method in invoked_from
        except:
            return False

    def does_method_return_boolean(self, return_exp):
        if return_exp['call_ret'].split("= ")[1] in ["false", "true"]:
            return True

    def analyze(self, setup: dict, task: Task):
        ams = "com.android.server.am.ActivityManagerService"

        last_action = helpers.get_last_processed_action(task, self.device.get_common_id())

        stacktrace = []
        to_instrument = []
        missing_perms = []
        user_restrictions = []
        methods = []
        appops_operations = []
        uid_works = True
        is_security_exception = False
        all_permissions_granted = True
        ignored_permissions = 0
        is_fully_executed = False
        exception = None
        api_exe_info = {
            "returns": False,
            "output": None
        }
        my_pid = None
        calling_pid = None
        pid_info = None
        uid_info = None

        config = helpers.get_task_config(task, self.device.get_common_id())
        current_phase = config['phase_name']

        while self.queue.qsize() > 0:
            result = self.queue.get()
            if "call_ret" in result:
                result['callstack'] = "{}\n{}".format(result['call_ret'], result['callstack'])

                ########################################################################
                # Getting the target class from the call stack of any api
                ########################################################################
                calls = result['callstack'].split("\n")
                for _, call in reversed(list(enumerate(calls))):
                    dot_splitted = call.split("(")[0].split(".")
                    method_name = dot_splitted[-1]
                    if setup['method'] == method_name:
                        target_class = ".".join(dot_splitted[:-1])
                        if target_class not in to_instrument:
                            to_instrument.append(target_class)
                        if '$' in target_class:
                            target_parent_class = target_class.split('$')[0]
                            if target_parent_class not in to_instrument:
                                to_instrument.append(target_parent_class)
                        if target_class == "android.app.ActivityManagerNative" and ams not in to_instrument:
                            to_instrument.append(ams)

                        package_name = ".".join(target_class.split(".")[:-1])
                        for _, call in reversed(list(enumerate(calls))):
                            tokens = call.split("(")[0].split(".")
                            pkg = ".".join(tokens[:-2])
                            if pkg == package_name:
                                related_pkg = ".".join(tokens[:-1])
                                if related_pkg not in to_instrument:
                                    to_instrument.append(related_pkg)


                ########################################################################
                # Formatting exceptions!
                ########################################################################
                if result['call_ret'].startswith("$init"):
                    result['call_ret'] = result['call_ret'].replace(", ", "")

                ########################################################################
                # Reporting Missing Permissions
                ########################################################################
                permission_is_missing = self.get_return_value(result) == "-1"
                is_check_uid_method = self.is_method_from_class(result, self.CHECK_UID_PERMISSION,
                                                                self.PACKAGE_MANAGER_SERVICE_CLASS)
                is_check_permission = self.is_method_from_class(result, self.CHECK_PERMISSION, self.CONTEXT_IMPL_CLASS)
                if (is_check_uid_method or is_check_permission) and permission_is_missing:
                    perm = self.get_parameter_at_index(result, 0)
                    uid = self.get_parameter_at_index(result, -1)

                    perm_formatted = "{}::{}".format(uid, perm) if setup['fake_uid'] != 1000 else "::{}".format(perm)
                    if perm_formatted not in missing_perms and perm_formatted not in setup['ignored_permissions']:
                        missing_perms.append(perm_formatted)
                    if perm_formatted in setup['ignored_permissions']:
                        ignored_permissions = ignored_permissions + 1

                ########################################################################
                # Reporting isIsolated
                ########################################################################
                cond1 = self.is_method_from_class(result, self.IS_ISOLATED, self.USER_HANDLE_CLASS)
                cond2 = self.has_parameter_of(result, setup['fake_uid'])
                if cond1 and cond2:
                    methods.append("{}::{}".format(setup['fake_uid'], self.IS_ISOLATED))

                ########################################################################
                # Reporting user restrictions
                ########################################################################
                if self.is_method(result, self.HAS_USER_RESTRICTION):
                    restriction = self.get_parameter_at_index(result, 0)
                    if restriction and restriction not in user_restrictions:
                        user_restrictions.append(restriction)

                ########################################################################
                # Reporting AppOps operations
                ########################################################################
                # Important: don't add the open parentheses to catch methods of the manager and service.
                if (self.is_method(result, self.NOTE_OP) or self.is_method(result, self.CHECK_OP) or
                        self.is_method(result, self.START_OP) or self.is_method(result, self.NOTE_OPERATION) or
                        self.is_method(result, self.CHECK_OPERATION) or self.is_method(result, self.START_OPERATION)):
                    try:
                        op_details = {
                            "method": result['call_ret'].split("(")[0],
                            "uid": result['call_ret'].split(", ")[1],
                            "op": int(helpers.find_between(result['call_ret'], "(", ",")),
                            "pkg": result['call_ret'].split(", ")[-1].split(")")[0],
                            "result": int(result['call_ret'].split(" = ")[1])
                        }
                        appops_operations = helpers.add_if_unique(op_details, appops_operations)
                    except Exception as e:
                        print(e, result['call_ret'])

                ########################################################################
                # Reporting privileged PID
                ########################################################################
                if "myPid()" in result['call_ret'] and current_phase != ACTION_CHANGE_PID:
                    _pid = int(result['call_ret'].split(" = ")[1])
                    pid_info = self.device.get_package_name_by_pid(_pid)
                    my_pid = pid_info['pid']

                if "getCallingPid()" in result['call_ret']:
                    calling_pid = int(result['call_ret'].split(" = ")[1])

                ########################################################################
                # Reporting security exceptions!
                ########################################################################
                if result['call_ret'].startswith("$init") and "Exception" in result['callstack']:
                    if "java.lang.SecurityException.<init>" in result['callstack'] and ignored_permissions == 0:
                        is_security_exception = True
                        uid_works = False

                    exception = {
                        "type": result['callstack'].split("\n")[3],
                        "location": result['callstack'].split("\n")[4],
                        "message": helpers.find_between(result['call_ret'], "(", ")").replace(", ", "")
                    }

                ########################################################################
                # Reporting API full execution
                ########################################################################
                if result['call_ret'].startswith("{}(".format(setup['method'])):
                    calls = result['callstack'].split("\n")
                    for i, _ in reversed(list(enumerate(calls))):
                        if i == 0:
                            continue
                        if "Stub.onTransact" in calls[i] and "{}(Native Method)".format(setup['method']) in calls[i-1]:
                            is_fully_executed = True
                            api_exe_info = {
                                "returns": True,
                                "output": result['call_ret'].split("= ")[1]
                            }

                ########################################################################
                # Not needed!
                ########################################################################
                if "getCallingUid()" in result['call_ret']:
                    calling_uid = int(result['call_ret'].split(" = ")[1])

                if "myUid()" in result['call_ret']:
                    _uid = int(result['call_ret'].split(" = ")[1])
                    uid_info = self.device.get_package_name_by_uid(_uid)
                    my_uid = uid_info['uid']

            stacktrace.append(result)

        out = []

        if len(missing_perms) > 0:
            uid_works = True

        """
        print("missing_perms_unsure >>>", missing_perms_unsure)

        if len(missing_perms) == 0 and len(missing_perms_unsure) > 0 and is_security_exception:
            for mpu in missing_perms_unsure:
                missing_perms.append(mpu)
        """

        if len(missing_perms) == 0 and is_security_exception:
            # Either a permission or something else is needed! Since we don't know the other thing, we just create
            #   a dummy new execution path!
            if "ProcessRecord{" in exception['message']:
                exception_msg = re.sub('ProcessRecord{(.*?):', 'ProcessRecord{', exception['message'], flags=re.DOTALL)
            else:
                exception_msg = exception['message']

            exception_msg = exception_msg + " "
            exception_msg = re.sub("@(.*?) ", '', exception_msg, flags=re.DOTALL)
            exception_to_add = "EXCEPTION::{}".format(exception_msg)
            missing_perms.append(exception_to_add)

        for perm in missing_perms:
            nxt_act = copy.deepcopy(self.action_template)
            nxt_act['permissions'].append(perm)
            nxt_act['uid'] = None if setup['fake_uid'] == self.device.get_app_uid(FUZZER_APP_PKG_NAME) \
                else setup['fake_uid']
            out.append(nxt_act)

        if last_action and 'data' in last_action and last_action['data']['parameters_hash'] == setup['parameters_hash']:
            if len(out) == 0:
                nxt_act = copy.deepcopy(self.action_template)
                out.append(nxt_act)

            for o in out:
                o['permissions'].extend(last_action['data']['permissions'])

        if setup['fake_pid'] != setup['pid'] and not is_security_exception:
            nxt_act = copy.deepcopy(self.action_template)
            nxt_act['pid'] = setup['fake_pid_name']
            nxt_act['uid'] = setup['fake_uid']
            nxt_act['userId'] = self.device.get_user_id(setup['fake_uid'])
            out.append(nxt_act)

        uids = helpers.get_task_config(task, self.device.get_common_id())['uids']
        if setup['fake_uid'] in uids and uid_works:
            for o in out:
                o['uid'] = setup['fake_uid']
                o['userId'] = self.device.get_user_id(setup['fake_uid'])

            if len(out) == 0:
                nxt_act = copy.deepcopy(self.action_template)
                nxt_act['uid'] = setup['fake_uid']
                nxt_act['userId'] = self.device.get_user_id(setup['fake_uid'])
                out.append(nxt_act)

        if calling_pid is not None and calling_pid == my_pid:
            nxt_act = copy.deepcopy(self.action_template)
            nxt_act['pid'] = self.device.get_package_name_by_pid(calling_pid)['name']
            nxt_act['uid'] = setup['fake_uid']
            nxt_act['userId'] = self.device.get_user_id(setup['fake_uid'])
            nxt_act['permissions'] = missing_perms
            out.append(nxt_act)

        if len(user_restrictions) > 0:
            if len(out) == 0:
                nxt_act = copy.deepcopy(self.action_template)
                out.append(nxt_act)
            for restriction in user_restrictions:
                for o in out:
                    o['user_restrictions'].append(restriction)

        if len(appops_operations) > 0:
            if len(out) == 0:
                nxt_act = copy.deepcopy(self.action_template)
                nxt_act['uid'] = setup['fake_uid']
                nxt_act['userId'] = self.device.get_user_id(setup['fake_uid'])
                out.append(nxt_act)
            for op in appops_operations:
                for o in out:
                    o['appOps'].append(op)

        if len(methods) > 0:
            for method in methods:
                for o in out:
                    o['methods'].append(method)

        if len(out) == 0 and is_fully_executed:
            nxt_act = copy.deepcopy(self.action_template)
            nxt_act['uid'] = setup['fake_uid']
            nxt_act['userId'] = self.device.get_user_id(setup['fake_uid'])
            out.append(nxt_act)

        for i in range(len(out)):
            out[i]['parameters_hash'] = setup['parameters_hash']

        to_instrument = [to_instrument[0]] if len(to_instrument) > 4 else to_instrument

        ret = {
            'execution_paths': out,
            'execution_outcome': api_exe_info,
            'pid_info': pid_info,
            'uid_info': uid_info,
            'uid_works': uid_works,
            'exception': {
                'is_security': is_security_exception,
                'data': exception
            },
            'appops_operations': appops_operations,
            'to_instrument': to_instrument,
            'stacktrace': stacktrace
        }

        if len(out) > 1 and helpers.hash_obj(out[0]['permissions']) == helpers.hash_obj(setup['permissions']):
            for i in range(1, len(out)):
                out[i]['permissions'].extend(out[0]['permissions'])
            del out[0]

        deferred_actions_path = helpers.get_deferred_actions_file_path(self.task, self.device.get_common_id())
        old_deferred_actions = helpers.read_json_file(deferred_actions_path)
        for i in range(len(old_deferred_actions)):
            old_deferred_actions[i] = old_deferred_actions[i]['data']
            old_deferred_actions[i]['processed'] = old_deferred_actions[i]['processed'] \
                if 'processed' in old_deferred_actions[i] else False

        # Breakdown many execution paths.
        deferred_actions = []
        executed_action = None
        for o in out:
            tmp = copy.deepcopy(ret)
            tmp['data'] = o
            tmp['data']['processed'] = False
            exists = helpers.object_exists(tmp['data'], old_deferred_actions)
            if not exists:
                del tmp['data']['processed']
                del tmp['execution_paths']
                del tmp['stacktrace']
                deferred_actions.append(tmp)

        unique_id = str(uuid.uuid4())
        deferred_actions_tmp = copy.deepcopy(deferred_actions)
        if len(deferred_actions) > 1:
            for deferred_action in deferred_actions:
                deferred_action['id'] = unique_id
                deferred_action['data']['pid'] = setup['fake_pid_name']
                for deferred_action_tmp in deferred_actions_tmp:
                    deferred_action['data']['ignored_permissions'].extend(deferred_action_tmp['data']['permissions'])
                    deferred_action['data']['ignored_permissions'] = list(set(deferred_action['data']['ignored_permissions']))

                for p in deferred_action['data']['permissions']:
                    if p in deferred_action['data']['ignored_permissions']:
                        deferred_action['data']['ignored_permissions'].remove(p)

                for p in setup['ignored_permissions']:
                    if p not in deferred_action['data']['ignored_permissions']:
                        deferred_action['data']['ignored_permissions'].append(p)

        if len(deferred_actions) > 0:
            deferred_actions[0]['processed'] = True
            executed_action = copy.deepcopy(deferred_actions[0])

        if not executed_action:
            executed_action = copy.deepcopy(ret)
            del executed_action['execution_paths']
            if last_action and 'data' in last_action \
                    and last_action['data']['parameters_hash'] == setup['parameters_hash']:
                executed_action['data'] = last_action['data']
            else:
                executed_action['data'] = copy.deepcopy(self.action_template)

            executed_action['data']['parameters_hash'] = setup['parameters_hash']

        if ('ignored_permissions' not in executed_action['data'] or len(executed_action['data']['ignored_permissions']) == 0) \
                and len(setup['ignored_permissions']) > 0:
            executed_action['data']['ignored_permissions'] = setup['ignored_permissions']

        # for deferred_action in deferred_actions[1:]:
        #     if last_action and ('deferred_action' in last_action or
        #                         helpers.get_actions_count(task, self.device.get_common_id()) == 1):
        #         deferred_action['data']['ignored_permissions'].extend(last_action['data']['ignored_permissions'])
        #         deferred_action['data']['ignored_permissions'] = list(set(executed_action['data']['ignored_permissions']))

        if not is_security_exception and exception:
            for p in executed_action['data']['ignored_permissions']:
                perm_tokens = p.split("::")
                if perm_tokens[1] in exception['message']:
                    expected_msg = "uid {} does not have {}.".format(perm_tokens[0], perm_tokens[1])
                    if expected_msg == exception['message']:
                        exception['message'] = p
                        break

            executed_action_tmp = copy.deepcopy(executed_action)
            if exception['message'] in executed_action['data']['ignored_permissions']:
                executed_action['data']['ignored_permissions'].remove(exception['message'])
                executed_action['data']['permissions'].append(exception['message'])

                sda_id = None
                executed_action_tmp_hash = helpers.hash_obj(executed_action_tmp['data'])
                stored_deferred_actions = helpers.get_deferred_actions(task, self.device.get_common_id())
                for sda in stored_deferred_actions:
                    if helpers.hash_obj(sda['data']) == executed_action_tmp_hash:
                        sda_id = sda['id']

                for sda in stored_deferred_actions:
                    if 'id' in sda and sda['id'] == sda_id:
                        if exception['message'] in sda['data']['ignored_permissions']:
                            sda['data']['ignored_permissions'].remove(exception['message'])
                        if exception['message'] not in sda['data']['permissions']:
                            sda['data']['permissions'].append(exception['message'])
                        else:
                            sda['processed'] = True

                helpers.persist_deferred_actions(task, self.device.get_common_id(), stored_deferred_actions)

        # if last_action and 'deferred_action' in last_action:
        #     executed_action['data']['ignored_permissions'].extend(last_action['data']['ignored_permissions'])
        #     executed_action['data']['ignored_permissions'] = list(set(executed_action['data']['ignored_permissions']))

        if 'processed' in executed_action:
            del executed_action['processed']

        if pid_info and 'name' in pid_info and pid_info['name']:
            config = helpers.get_task_config(task, self.device.get_common_id())

            name_hash = "{}:{}".format(pid_info['name'], setup['parameters_hash'])
            if name_hash not in config['pids'] and name_hash not in config['pids_done']:
                config['pids'].append(name_hash)

            helpers.persist_task_config(task, self.device.get_common_id(), config)

        executed_action['stacktrace'] = stacktrace

        return executed_action, deferred_actions

    def enqueue_result(self, result):
        self.queue.put(result)

    def __init__(self, device: Device, task: Task):
        self.device = device
        self.task = task
        self.queue = queue.Queue()
