from includes.constants import SERVICE_NAME_POSITION, API_NAME_POSITION, RETURN_TYPE_POSITION, PARAMETERS_POSITION


def get_api_name(api_raw):
    return api_raw.split("|")[API_NAME_POSITION]


def get_service_name(api_raw):
    return api_raw.split("|")[SERVICE_NAME_POSITION]


def get_parameters(api_raw):
    return api_raw.split("|")[PARAMETERS_POSITION]


def get_return_type(api_raw):
    return api_raw.split("|")[RETURN_TYPE_POSITION]


class Task:

    def get_task_type(self):
        return self.task_type

    def get_api_raw(self) -> str:
        return self.api_raw

    def set_api(self, api: str):
        self.api = api

    def get_api(self):
        return self.api

    def set_service(self, service: str):
        self.service = service

    def get_service(self):
        return self.service

    def set_authority(self, authority: str):
        self.authority = authority

    def get_authority(self):
        return self.authority

    def set_cp_method(self, cp_method: str):
        self.cp_method = cp_method

    def get_cp_method(self):
        return self.cp_method

    def __init__(self, task_type: str, api_raw: str):
        self.task_type = task_type
        self.api_raw = api_raw
        self.api = None
        self.service = None
        self.authority = None
        self.cp_method = None
