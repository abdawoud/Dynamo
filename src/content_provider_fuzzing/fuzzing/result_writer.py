import json
import time
from pathlib import Path
from typing import List

from src.content_provider_fuzzing.cp_api_models import ApiFuzzingResult
from src.content_provider_fuzzing.deencoders.json_encoder import JsonEncoder
from utils.helpers import get_specific_out_dir


class ResultWriter:
    def __init__(self, filename: str):
        self.filename = filename

        cp_fuzzing_results_dir_path = Path(get_specific_out_dir('cp_fuzzing_results'))
        self.results_dir = cp_fuzzing_results_dir_path / time.strftime("%Y_%m_%d_%H_%M_%S", time.gmtime())

    def write(self, results: List[ApiFuzzingResult]):
        self.results_dir.mkdir(parents=True, exist_ok=True)

        results_file = self.results_dir / self.filename
        with open(results_file.as_posix(), 'w') as f:
            results_string = json.dumps(results, cls=JsonEncoder, indent=4)
            f.write(results_string)
