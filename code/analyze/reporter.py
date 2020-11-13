from models.task import Task
from models.device import Device

from utils import helpers
from includes.constants import FUZZER_APP_PKG_NAME, FIRST_USER_ID


class Reporter:

    def similar_exception(self, exception: str, permissions_list: list) -> bool:
        """
        for perm in permissions_list:
            if "EXCEPTION::" in perm:
                return True
        """
        return False

    def report_action(self, task: Task, action: dict, setup: dict, invocation_result: dict):
        actions_file_path = helpers.get_api_actions_file_path(self.task, self.device.get_common_id())
        actions = helpers.read_json_file(actions_file_path)

        try:
            last_action = actions[self.task.get_service()][self.task.get_api()]['ordered_iterations'][-1]
        except:
            last_action = None

        if last_action:
            for permission in action['data']['permissions']:
                if permission.startswith("EXCEPTION:") and permission in last_action['data']['permissions'] and \
                        last_action['data']['parameters_hash'] == setup['parameters_hash']:
                    action['data'] = last_action['data']

        if invocation_result:
            action['execution_outcome']['returns'] = invocation_result['returns']
            action['execution_outcome']['output'] = invocation_result['output']
            action['execution_outcome']['exception'] = invocation_result['exception']

        action['data']['permissions'] = list(set(action['data']['permissions']))
        action['data']['permissions'].sort()
        action['data']['ignored_permissions'].sort()

        actions[self.task.get_service()][self.task.get_api()]['ordered_iterations'].append(action)

        helpers.write_json_file(actions_file_path, actions)

        # Increment the parameters set count
        config = helpers.get_task_config(task, self.device.get_common_id())

        for clazz in action['to_instrument']:
            if clazz and clazz not in config['classes']:
                config['classes'].append(clazz)

        if self.device.get_app_uid(FUZZER_APP_PKG_NAME) == setup['fake_uid']:
            fuzzed_uid = None
        elif self.device.get_app_uid(FUZZER_APP_PKG_NAME) == (setup['fake_uid'] % FIRST_USER_ID):
            fuzzed_uid = FIRST_USER_ID
        else:
            fuzzed_uid = setup['fake_uid']

        formatted_hash = "{}:{}".format(fuzzed_uid, setup['parameters_hash'])

        repeated_action = helpers.is_repeated_action(task, self.device.get_common_id(), action['data'], 1)
        if repeated_action:
            if formatted_hash not in config['parameters_done']:
                config['parameters_done'][formatted_hash] = 1
            else:
                config['parameters_done'][formatted_hash] = config['parameters_done'][formatted_hash] + 1

        helpers.persist_task_config(task, self.device.get_common_id(), config)

    def report_deferred_actions(self, deferred_actions: list):
        deferred_actions_file_path = helpers.get_deferred_actions_file_path(self.task, self.device.get_common_id())
        deferred_actions_content = helpers.read_json_file(deferred_actions_file_path)

        old_deferred_actions_hashed = []
        for deferred_action in deferred_actions_content:
            old_deferred_actions_hashed.append(helpers.hash_obj(deferred_action['data']))

        changed = False
        for deferred_action in deferred_actions:
            deferred_action['data']['permissions'] = list(set(deferred_action['data']['permissions']))
            deferred_action['data']['permissions'].sort()
            deferred_action['data']['ignored_permissions'].sort()
            hashed_deferred_action = helpers.hash_obj(deferred_action['data'])
            if hashed_deferred_action not in old_deferred_actions_hashed:
                changed = True
                deferred_actions_content.append(deferred_action)

        if changed:
            helpers.write_json_file(deferred_actions_file_path, deferred_actions_content)

    def __init__(self, device: Device, task: Task):
        self.device = device
        self.task = task
