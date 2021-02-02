import argparse
import signal
import sys
import threading
import time

from includes.constants import LOCALHOST, DEFAULT_DEVICE_TO_USER
from models.device import Device
from src.adb.adb_connection import AdbConnection
from src.adb.adb_server import AdbServer
from src.content_provider_fuzzing.cp_fuzzing_main import CpFuzzingMain
from src.worker import Worker
from utils import helpers
from utils.cuttlefish import Cuttelfish

# import ptuner

workers = []


def main(args):
    signal.signal(signal.SIGINT, signal_handler)

    cuttlefish = Cuttelfish()
    cf_dir = "path/to/cuttlefish/binaries"

    parser = argparse.ArgumentParser(description='Fuzz services and APIs.')
    parser.add_argument('--fuzz-content-providers', dest='fuzz_cps', action='store_true')
    parser.add_argument('--device', dest='device', default=None,
                        help='Targeted ADB device Id')
    parser.add_argument('--service', dest='service', default=None,
                        help='The name of the service to fuzz')
    parser.add_argument('--api', dest='api', default=None,
                        help='The name of the API to fuzz. This requires the --service attribute to be set.')
    parser.add_argument('--reset-service', dest='reset_service', default=None, action='store_true',
                        help='To reset the APIs stats of the selected service. This requires the --service to be set.')
    parser.add_argument('--reset-api', dest='reset_api', default=None, action='store_true',
                        help='To reset the API stats. This requires the --service and --api to be set.')
    parser.add_argument('--cf-dir', dest='cf_dir_default', default=cf_dir,
                        help='Absolute path to the cuttlefish binary directory. Default: {}'.format(cf_dir))
    parser.add_argument('--crunch-parameters', dest='crunch_parameters', default=None, action='store_true',
                        help='Set if parameters need to be (re)parsed from the custome_parameters.json file. '
                             'Exit script when done')
    args = parser.parse_args(args)

    selected_device = args.device
    selected_service = args.service
    selected_api = args.api

    worker = None
    if args.fuzz_cps:
        # Fuzz content provider using magic values file from static analysis
        CpFuzzingMain(main_script_path=__file__).main()

    else:
        reset_api = args.reset_api
        if reset_api and (not selected_service or not selected_api):
            parser.error("--reset-api requires --service and --api.")
        reset_service = args.reset_service
        if reset_service and not selected_service:
            parser.error("--reset-service requires --service.")
        cf_dir = args.cf_dir_default if args.cf_dir_default else cf_dir
        crunch_parameters = args.crunch_parameters

        print(selected_device, selected_service, selected_api, reset_api, reset_service, cf_dir)

        locks = {}

        adb_server = AdbServer(host=LOCALHOST, port=None)
        connected_devices = adb_server.get_connected_devices()
        print("# of connected devices: {}".format(len(connected_devices)))

        for i in range(3):
            connected_devices = adb_server.get_connected_devices()
            time.sleep(1)

        if len(connected_devices) == 0 and selected_device == DEFAULT_DEVICE_TO_USER:
            cuttlefish.stop_process(cf_dir)
            time.sleep(3)
            cuttlefish.start_process(cf_dir)
            time.sleep(3)

        connected_devices = adb_server.get_connected_devices()
        max_tries = 60
        while len(connected_devices) == 0:
            print("- Getting connected devices")
            time.sleep(1)
            connected_devices = adb_server.get_connected_devices()
            max_tries = max_tries - 1
            if max_tries == 0:
                print("Exceeded the maximum tries for getting the devices!")
                sys.exit(-1)

        for device_name in connected_devices:
            if selected_device:
                if device_name != selected_device:
                    print('skipping {}'.format(device_name))
                    continue

            adb_connection = AdbConnection(adb_server, device_id=device_name)
            device = Device(adb_connection)

            device_common_id = device.get_common_id()

            if crunch_parameters:
                print(device.get_device_id(), "Parameters are going to be parsed...")
                ptuner.craft_parameters()
                print(device.get_device_id(), "Done parsing the parameters!")
                sys.exit(0)

            if reset_api:
                print(device.get_device_id(), "Resetting API stats")
                helpers.reset_api_stats(device_common_id, selected_service, selected_api)
                print(device.get_device_id(), "Done resetting the API's stats!")
                sys.exit(0)

            if reset_service:
                print(device.get_device_id(), "Resetting service stats")
                helpers.reset_service_stats(device_common_id, selected_service)
                print("+ Done resetting service's stats!")
                sys.exit(0)

            if device_common_id not in locks:
                locks[device_common_id] = threading.Lock()

            # Clean run!
            """
            device.reboot(wait=True)
            while device.is_booting():
                print(device.get_common_id(), "still recovering from first reboot...")
                time.sleep(1)
            """

            worker = Worker(device, locks[device_common_id], selected_service, selected_api)

        worker.start()
        workers.append(worker)


def signal_handler(sig, frame):
    for worker in workers:
        worker.stop()
    sys.exit(0)


if __name__ == "__main__":
    argv = sys.argv[1:]  # Let's us pass arguments in tests
    main(argv)
