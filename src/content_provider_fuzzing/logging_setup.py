import logging
from pathlib import Path

import coloredlogs


def setup_logging(log_file_path: Path):
    coloredlogs.install(level='INFO')

    file_handler = logging.FileHandler(filename=log_file_path, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger('')
    root_logger.addHandler(file_handler)
