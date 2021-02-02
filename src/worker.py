import traceback

from src.base_worker import BaseWorker
from models.device import Device
from utils import helpers
from includes.constants import APIS, FUZZER_APP_PKG_NAME, MERAKI_PKG_NAME
import copy
import threading
import time
from utils.cuttlefish import Cuttelfish
from models.task import Task, get_api_name, get_service_name
from typing import Any
from threading import Lock
from .instrumentation.instrumentor import Instrumentor
from src.analyze.analyzer import Analyzer
from src.analyze.reporter import Reporter


class Worker(BaseWorker):
    class WorkerThread(threading.Thread):
        def __init__(self, worker: Any, lock: Lock):
            threading.Thread.__init__(self)
            self.worker = worker
            self.lock = lock
            self.cuttlefish = Cuttelfish()

        def run(self):
            self.worker.prepare()
            self.worker.create_api_tasks_files()
            self.worker.clean_stats()

            print(self.worker.device.get_device_id(), "Starting ", self.name)
            while True:
                Worker.process_data(self.worker, self.lock)

    def prepare(self):
        while True:
            try:
                super().prepare()  # installs & starts frida

                success = self.install_app(FUZZER_APP_PKG_NAME)
                if not success:
                    error = "Cannot install fuzzing app"
                    self.logger.elog(error)
                    raise Exception(error)
                else:
                    self.logger.ilog("Fuzzing App installed")

                success = self.install_app(MERAKI_PKG_NAME)
                if not success:
                    error = "Cannot install device manager app"
                    self.logger.elog(error)
                    raise Exception(error)
                else:
                    self.logger.ilog("Device Manager App installed")

                success = self.create_on_device_fuzzing_private_files()
                if not success:
                    error = "Cannot create the necessary on-device fuzzing files"
                    self.logger.elog(error)
                    raise Exception(error)
                else:
                    self.logger.ilog("On-device private fuzzing files were created successfully.")

                success = self.start_fuzzing_app_main_activity()
                if not success:
                    error = "Cannot start main activity"
                    self.logger.elog(error)
                    raise Exception(error)
                else:
                    self.logger.ilog("Fuzzing App's main activity started")

                time.sleep(1)

                success = self.prepare_api_list()
                if not success:
                    error = "Cannot prepare the APIs list"
                    self.logger.elog(error)
                    raise Exception(error)
                else:
                    self.logger.ilog("API list is pulled successfully")

                # Early exit if the map is found.
                self.instrumentor.construct_service_process_map()

                break
            except Exception as e:
                traceback.print_exc()
                self.logger.exception(__file__, self.prepare, e)
                time.sleep(5)

    def restart_cuttlefish(self):
        cuttlefish = Cuttelfish()
        path = "path/to/cuttlefish/binaries"
        cuttlefish.stop_process(path)
        time.sleep(3)
        cuttlefish.start_process(path)
        time.sleep(3)

    def process_data(self, lock: Lock):
        lock.acquire()

        if self.selected_service:
            if self.selected_api:
                service_api = "{}:{}".format(self.selected_service, self.selected_api)
                task = self.pull_task(selected_service_api=service_api)
            else:
                task = self.pull_task(selected_service=self.selected_service)
        else:
            task = self.pull_task()

        lock.release()

        while True:
            count = 0
            wait_max_count = 20
            while self.device.is_booting():
                time.sleep(1)
                count = count + 1
                if count % 3:
                    self.logger.ilog("still booting...")
                    wait_max_count = wait_max_count - 1
                if wait_max_count == 0:
                    break

            config = helpers.get_task_config(task, self.device.get_common_id())
            if 'done' in config and config['done']:
                lock.acquire()
                finished = self.finish_task(task)
                lock.release()
                if not finished:
                    self.logger.elog("{} was not marked as finished!".format(task.get_api_raw()))
                break

            if self.exit_thread:
                lock.acquire()
                enqueued = self.enqueue_task(task)
                lock.release()

                if not enqueued:
                    self.logger.elog("{} was not enqueued!".format(task.get_api_raw()))
                break

            success = self.install_and_run_frida()
            if not success:
                error = "Cannot run frida!"
                self.logger.elog(error)
                time.sleep(2)
                continue
            else:
                self.logger.ilog("Frida is installed and running")

            setup = self.instrumentor.prepare_fuzzing_file(task)
            if not setup:
                config['done'] = True
                helpers.persist_task_config(task, self.device.get_common_id(), config)
                continue
            if task.get_task_type() == APIS:
                try:
                    self.execute_api_task(task, setup)
                except Exception as e:
                    traceback.print_exc()
                    print(self.device.get_common_id(), str(e))
                    self.device.reboot(wait=True)
                    pass
                time.sleep(1)
            else:
                raise NotImplemented

    def start(self):
        self.worker_thread.start()

    def stop(self):
        print(self.device.get_device_id(), "Exiting the thread based on Ctl+c")
        self.exit_thread = True

    def start_fuzzing_app_main_activity(self, user_id: int = 0):
        return self.device.start_fuzzing_app_main_activity(user_id)

    def prepare_api_list(self) -> bool:
        return self.device.pull_api_list()

    def create_on_device_fuzzing_private_files(self) -> bool:
        return self.device.create_on_device_fuzzing_private_files()

    def create_api_tasks_files(self):
        helpers.create_api_tasks_files(self.device_common_id)

    def clean_stats(self):
        helpers.clean_stats(self.device_common_id)

    def reset_api_stats(self, service: str, api: str):
        helpers.reset_api_stats(self.device_common_id, service, api)

    def reset_service_stats(self, service: str):
        helpers.reset_service_stats(self.device_common_id, service)

    def generate_content_providers_uris(self):
        raise NotImplemented

    def generate_bound_services_list(self):
        raise NotImplemented

    def pull_task(self, selected_service_api: str = None, selected_service: str = None) -> Task:
        api_raw = helpers.pull_api_task_recursively(self.device_common_id, selected_service_api, selected_service)
        if api_raw:
            task = Task(APIS, api_raw)
            task.set_api(get_api_name(api_raw))
            task.set_service(get_service_name(api_raw))

            return task

        raise NotImplemented

    def enqueue_task(self, task: Task):
        if task.get_task_type() == APIS:
            return helpers.enqueue_api_task(self.device_common_id, task)

        raise NotImplemented

    def finish_task(self, task: Task):
        if task.get_task_type() == APIS:
            return helpers.finish_api_task(self.device_common_id, task)

        raise NotImplemented

    def validate_error_counters(self, task: Task, setup: dict):
        config = helpers.get_task_config(task, self.device.get_common_id())
        print(config['errors'])

        if 'historical_service_not_invoked' not in config['errors']:
            config['errors']['historical_service_not_invoked'] = 0
        if 'historical_no_traces' not in config['errors']:
            config['errors']['historical_no_traces'] = 0
        if 'historical_not_instrumented' not in config['errors']:
            config['errors']['historical_not_instrumented'] = 0

        historical_errors = config['errors']['historical_service_not_invoked'] + config['errors']['historical_no_traces'] + config['errors']['historical_not_instrumented']
        if historical_errors >= 15:
            config['done'] = True
            config['errored'] = True
            helpers.persist_task_config(task, self.device.get_common_id(), config)
            if self.device.is_cuttlefish_emulator():
                self.restart_cuttlefish()
            else:
                self.device.reboot(wait=True)
            return

        if config['errors']['not_instrumented'] > 3 or config['errors']['service_not_invoked'] > 3 or \
                config['errors']['no_traces'] >= 3:
            config['errors']['not_instrumented'] = 0
            config['errors']['service_not_invoked'] = 0
            config['errors']['no_traces'] = 0
            helpers.persist_task_config(task, self.device.get_common_id(), config)
            if self.device.is_cuttlefish_emulator():
                self.restart_cuttlefish()
            else:
                self.device.reboot(wait=True)

    def execute_api_task(self, task: Task, setup: dict):
        print(self.device.get_device_id(), setup)

        if setup is None:
            return

        success = self.device.push_fuzzing_file(setup, setup['profile'])
        if not success:
            raise Exception("Cannot push the fuzzing file into device!")

        analyzer = Analyzer(self.device, task)

        success, processes = self.instrumentor.instrument_and_wait(task, setup, analyzer)

        if not success:
            print("(-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) \n"
                  "(-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) \n"
                  "(-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-)")

            self.validate_error_counters(task, setup)
            raise Exception("Cannot instrument the target processes!")

        action, deferred_actions = analyzer.analyze(setup, task)

        config = helpers.get_task_config(task, self.device.get_common_id())
        if 'no_traces' not in config['errors']:
            config['errors']['no_traces'] = 0
        if 'historical_no_traces' not in config['errors']:
            config['errors']['historical_no_traces'] = 0

        invocation_result = self.device.pull_invocation_result(setup['profile'])
        invocation_result_summarized = copy.deepcopy(invocation_result)
        if 'exception' in invocation_result_summarized:
            del invocation_result_summarized['exception']
        print(self.device.get_device_id(), "invocation_result", invocation_result_summarized)

        stacktrace_reported, invocation_succeeded = helpers.stacktrace_was_reported_before(task, self.device.get_common_id())
        if len(action['stacktrace']) == 0 and (stacktrace_reported or invocation_succeeded):
            err_msg = "Unlike previous iterations, no traces were reported!"
            self.logger.ilog(err_msg)

            if not invocation_result:
                config['errors']['no_traces'] = config['errors']['no_traces'] + 1
                config['errors']['historical_no_traces'] = config['errors']['historical_no_traces'] + 1
                helpers.persist_task_config(task, self.device.get_common_id(), config)

                print("(-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) \n"
                      "(-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) \n"
                      "(-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-) (-)")

                self.validate_error_counters(task, setup)

                err_msg = "Unlike previous iterations, no traces were reported and no invocation-result file!"
                self.logger.ilog(err_msg)
                raise Exception(err_msg)
            else:
                err_msg = "No traces, but API executed successfully!"
                self.logger.ilog(err_msg)
        else:
            config['errors']['no_traces'] = 0
            helpers.persist_task_config(task, self.device.get_common_id(), config)

        if invocation_result and 'exception' in invocation_result and invocation_result['exception'] == "null":
            print("(+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) \n"
                  "(+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) \n"
                  "(+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+) (+)")
        else:
            print("(?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) \n"
                  "(?) (?) (?) (?) (?) (?) (?) FIX THIS IF YOU CAN (?) (?) (?) (?) (?) (?) \n"
                  "(?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?) (?)")

        # Rewards for everyone!!!
        if 'historical_no_traces' in config['errors'] and config['errors']['historical_no_traces'] >= 0.3:
            config['errors']['historical_no_traces'] = config['errors']['historical_no_traces'] - 0.3

        if 'historical_service_not_invoked' in config and config['errors']['historical_service_not_invoked'] >= 0.3:
            config['errors']['historical_service_not_invoked'] = config['errors']['historical_service_not_invoked'] - 0.3

        if 'historical_not_instrumented' in config and config['errors']['historical_not_instrumented'] >= 0.3:
            config['errors']['historical_not_instrumented'] = config['errors']['historical_not_instrumented'] - 0.3

        helpers.persist_task_config(task, self.device.get_common_id(), config)

        reporter = Reporter(self.device, task)
        reporter.report_action(task, action, setup, invocation_result)
        if len(deferred_actions) > 0:
            reporter.report_deferred_actions(deferred_actions)

        self.logger.ilog("Killing instrumented processes and restarting...")
        print(self.device.get_device_id(), processes)
        if self.device.is_su_c_supported():
            self.device.reboot(True)
        else:
            self.device.kill_processes(processes)
        print("processes killed")

        if self.device.is_su_c_supported():
            pixel_is_ready = self.device.is_pixel_device_ready()
            while not pixel_is_ready:
                pixel_is_ready = self.device.is_pixel_device_ready()
                if not pixel_is_ready:
                    print(self.device.get_device_id(), "Still booting the pixel device...")
                time.sleep(1)

            pixel_is_ready = self.device.is_pixel_device_ready("com.android.keychain")
            while not pixel_is_ready:
                pixel_is_ready = self.device.is_pixel_device_ready("com.android.keychain")
                if not pixel_is_ready:
                    print(self.device.get_device_id(), "Still booting the pixel device...")
                time.sleep(1)

            print(self.device.get_device_id(), "Pixel emulator is detected. Sleeping 5 more seconds!")

        if self.device.is_cuttlefish_emulator():
            wait_max_count = 2 if setup['service'] in ['vold', 'installd'] else 60
            emulator_is_ready = self.device.is_cuttlefish_emulator_ready()
            while not emulator_is_ready:
                emulator_is_ready = self.device.is_cuttlefish_emulator_ready()
                if not emulator_is_ready:
                    print(self.device.get_device_id(), "Still booting the cuttlefish emulator...")
                    wait_max_count = wait_max_count - 1
                time.sleep(1)
                if wait_max_count == 0:
                    break

            wait_max_count = 2 if setup['service'] in ['vold', 'installd'] else 60
            pixel_is_ready = self.device.is_pixel_device_ready("com.android.localtransport")
            while not pixel_is_ready:
                pixel_is_ready = self.device.is_pixel_device_ready("com.android.localtransport")
                if not pixel_is_ready:
                    print(self.device.get_device_id(), "Still booting the cuttlefish emulator...")
                    wait_max_count = wait_max_count - 1
                time.sleep(1)
                if wait_max_count == 0:
                    break

            print(self.device.get_device_id(), "Cuttlefish emulator is detected. Sleeping 10 more seconds!")
            time.sleep(10)

        self.validate_error_counters(task, setup)

    def __init__(self, device: Device, lock: Any, selected_service: str = None, selected_api: str = None):
        super().__init__(device)
        self.selected_service = selected_service
        self.selected_api = selected_api
        self.instrumentor = Instrumentor(self.device)
        self.worker_thread = Worker.WorkerThread(self, lock)

    def __del__(self):
        self.logger.ilog("Exiting....")
