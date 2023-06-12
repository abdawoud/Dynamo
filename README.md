# Dynamo: Tool & Results
Please, see Results directory for permission mappings of Android 6 and 10.

## Content Provider Fuzzing
### Working configuration
- Ubuntu 20.04.1 LTS (Google Cloud Compute Engine)
- Python 3.8

### Setup
1. Install & setup cuttlefish - https://source.android.com/setup/create/cuttlefish
2. Build content provider fuzzer - https://github.com/AndroidPermissionMapping/Content-Provider-Fuzzer
3. Extract magic values from an android image - https://github.com/AndroidPermissionMapping/magicextractor
4. Copy `cp_fuzz_config.json.example` to `cp_fuzz_config.json` and update the config file.
5. Run `pip install -r requirements.txt`
6. Run `main.py --fuzz-content-providers`
7. Check `out/cp_fuzzing_results/yyyy-mm-dd-hh-mm-ss/*`

## Service Api Fuzzing
### Setup
1. Install & setup cuttlefish - https://source.android.com/setup/create/cuttlefish
2. Run `pip install -r requirements.txt`
3. Find out which api in which service you want to fuzz. Run `main.py --cf-dir "/home/user/cf" --device "127.0.0.1:6520" --api <API_NAME> --service <SERVICE_NAME>`
4. Check `out/*`

### Known Issues / Workarounds
#### Wget not enough values to unpack
```
#:~/dynamo_documentation/Dynamo$ python3 main.py --cf-dir "/home/user/cf" --device "127.0.0.1:6520" --api "requestAuthorization" --service "incidentcompanion"
127.0.0.1:6520 incidentcompanion requestAuthorization None None /home/user/cf
# of connected devices: 0
= Stopping Cuttlefish emulator...
+ Cuttlefish emulator is stopped!
= Running Cuttlefish emulator...
+ Cuttlefish emulator booted!
100% [........................................................................] 13383236 / 13383236Traceback (most recent call last):
  File "/home/user/dynamo_documentation/Dynamo/src/worker.py", line 39, in prepare
    super().prepare()  # installs & starts frida
  File "/home/user/dynamo_documentation/Dynamo/src/base_worker.py", line 22, in prepare
    success = self.install_and_run_frida()
  File "/home/user/dynamo_documentation/Dynamo/src/base_worker.py", line 36, in install_and_run_frida
    path = helpers.get_frida_server(abi)
  File "/home/user/dynamo_documentation/Dynamo/utils/helpers.py", line 403, in get_frida_server
    wget.download(url, out=download_dir)
  File "/usr/local/lib/python3.8/dist-packages/wget.py", line 533, in download
    filename = filename_fix_existing(filename)
  File "/usr/local/lib/python3.8/dist-packages/wget.py", line 269, in filename_fix_existing
    name, ext = filename.rsplit('.', 1)
ValueError: not enough values to unpack (expected 2, got 1)
/home/user/dynamo_documentation/Dynamo/src/worker.py prepare not enough values to unpack (expected 2, got 1)
```
Run `rm res/frida-server*` to solve this problem.

#### self.pull_task(selected_service_api=service_api) - NotImplemented
```
#: python3 -u /home/user/dynamo_doc/main.py --cf-dir /home/user/cf --device 127.0.0.1:6520 --api getWifiEnabled --service wifi
127.0.0.1:6520 wifi getWifiEnabled None None /home/user/cf
# of connected devices: 1
100% [....................................................] 13383236 / 13383236127.0.0.1:6520 Frida is running!
127.0.0.1:6520 Frida is installed and running
127.0.0.1:6520 Uninstalling the app...
127.0.0.1:6520 Installing the app...
127.0.0.1:6520 Fuzzing App installed
127.0.0.1:6520 Device Manager App installed
127.0.0.1:6520 On-device private fuzzing files were created successfully.
127.0.0.1:6520 Fuzzing App's main activity started
127.0.0.1:6520 API list is pulled successfully
127.0.0.1:6520 Starting  Thread-1
Exception in thread Thread-1:
Traceback (most recent call last):
  File "/usr/lib/python3.8/threading.py", line 932, in _bootstrap_inner
    self.run()
  File "/home/user/dynamo_doc/src/worker.py", line 34, in run
    Worker.process_data(self.worker, self.lock)
  File "/home/user/dynamo_doc/src/worker.py", line 106, in process_data
    task = self.pull_task(selected_service_api=service_api)
  File "/home/user/dynamo_doc/src/worker.py", line 213, in pull_task
    raise NotImplemented
TypeError: exceptions must derive from BaseException
127.0.0.1:6520 Exiting....

Process finished with exit code 0
```
This means your api name, service name combinations does not exist. You need to find a valid configuration.
