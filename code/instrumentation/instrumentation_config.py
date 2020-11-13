from typing import List
from includes.constants import HASH_PLACEHOLDER


class InstrumentationConfig:

    def get_fake_profile(self) -> int:
        return self.fake_profile

    def set_fake_profile(self, fake_profile: int):
        self.fake_profile = fake_profile

    def get_real_profile(self) -> int:
        return self.real_profile

    def set_real_profile(self, real_profile: int):
        self.real_profile = real_profile

    def get_fake_uid(self) -> int:
        return self.fake_uid

    def set_fake_uid(self, fake_uid):
        self.fake_uid = fake_uid

    def get_real_uid(self) -> int:
        return self.real_uid

    def set_real_uid(self, real_uid):
        self.real_uid = real_uid

    def get_fake_pid(self) -> int:
        return self.fake_pid

    def set_fake_pid(self, fake_pid: int):
        self.fake_pid = fake_pid

    def get_fake_pid_name(self) -> str:
        return self.fake_pid_name

    def set_fake_pid_name(self, fake_pid_name: str):
        self.fake_pid_name = fake_pid_name

    def get_real_pid(self) -> int:
        return self.real_pid

    def set_real_pid(self, real_pid: int):
        self.real_pid = real_pid

    def get_granted_permissions(self) -> List[str]:
        return self.granted_permissions

    def set_granted_permissions(self, granted_permissions: List[str]):
        self.granted_permissions = granted_permissions

    def get_user_restrictions(self) -> List[str]:
        return self.user_restrictions

    def set_user_restrictions(self, user_restrictions: List[str]):
        self.user_restrictions = user_restrictions

    def get_granted_app_ops_permissions(self) -> List[str]:
        return self.granted_app_ops_permissions

    def set_granted_app_ops_permissions(self, granted_app_ops_permissions: List[str]):
        self.granted_app_ops_permissions = granted_app_ops_permissions

    def get_classes_to_instrument(self) -> List[str]:
        return self.classes_to_instrument

    def set_classes_to_instrument(self, classes_to_instrument: List[str]):
        self.classes_to_instrument = classes_to_instrument

    def get_ignored_permissions(self) -> List[str]:
        return self.ignored_permissions

    def set_ignored_permissions(self, ignored_permissions: List[str]):
        self.ignored_permissions = ignored_permissions

    def get_force_switch_profile(self) -> bool:
        return self.force_switch_profile

    def set_force_switch_profile(self, force_switch_profile: bool):
        self.force_switch_profile = force_switch_profile

    def get_fuzzed_parameters(self) -> list:
        return self.fuzzed_parameters

    def set_fuzzed_parameters(self, fuzzed_parameters: list):
        self.fuzzed_parameters = fuzzed_parameters

    def get_fuzzed_parameters_hash(self) -> str:
        return self.parameters_hash

    def set_fuzzed_parameters_hash(self, parameters_hash: str):
        self.parameters_hash = parameters_hash

    def __init__(self):
        self.fake_profile = -1
        self.real_profile = -1
        self.fake_uid = -1
        self.real_uid = -1
        self.fake_pid = -1
        self.fake_pid_name = None
        self.real_pid = -1
        self.granted_permissions = []
        self.user_restrictions = []
        self.granted_app_ops_permissions = []
        self.classes_to_instrument = []
        self.ignored_permissions = []
        self.force_switch_profile = False
        self.fuzzed_parameters = []
        self.parameters_hash = HASH_PLACEHOLDER
