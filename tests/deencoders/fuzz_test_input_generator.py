import json
from typing import List, Dict


class FuzzTestInputGenerator:
    def __init__(self, cp_class_name, cp_uri):
        self.cp_class_name = cp_class_name
        self.cp_uri = cp_uri

    def generate(self, fuzz_data: List[Dict]) -> str:
        fuzz_input = {
            'className': self.cp_class_name,
            'data': fuzz_data
        }
        return json.dumps(fuzz_input)
