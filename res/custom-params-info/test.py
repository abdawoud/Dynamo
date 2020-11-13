import json
import os


def file_exists(path: str) -> bool:
    return os.path.isfile(path)

def read_file(path: str) -> (bool, str):
    try:
        if not file_exists(path):
            raise FileNotFoundError

        file = open(path, 'r')
        content = file.read()
        file.close()
        return True, content
    except Exception as e:
    	raise e
    	return False, str(e)

def read_json_file(path: str) -> (bool, dict):
    success, data = read_file(path)
    if success:
        return json.loads(data)
    else:
        return None

apis = read_json_file('custom_parameters.json')
idx = 1
for api in apis:
	count = 1
	for param in apis[api]:
		count = len(param) * count
	if count >= 10:
		print(idx, count, api)
		idx = idx + 1