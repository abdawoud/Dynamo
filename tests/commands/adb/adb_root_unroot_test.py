import re
from typing import List


def test_adb_root(adb_cmd_factory):
    if is_root(adb_cmd_factory):
        cmd = adb_cmd_factory.unroot()
        cmd.execute()

    cmd = adb_cmd_factory.root()
    cmd.execute()

    assert is_root(adb_cmd_factory)


def test_adb_unroot(adb_cmd_factory):
    if not is_root(adb_cmd_factory):
        cmd = adb_cmd_factory.root()
        cmd.execute()

    cmd = adb_cmd_factory.unroot()
    cmd.execute()

    assert not is_root(adb_cmd_factory)


def is_root(adb_cmd_factory) -> bool:
    cmd = adb_cmd_factory.shell('id')
    output = cmd.execute()
    return extract_uid_from_id_cmd(output) == 0


def extract_uid_from_id_cmd(output: List[str]) -> int:
    pattern = re.compile('uid=([0-9]*)')
    match = re.match(pattern, output[0])
    return int(match.group(1))
