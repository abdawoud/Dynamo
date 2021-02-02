from typing import List


def test_reverse_port_forwarding(adb_cmd_factory):
    host_port = 5678
    device_port = 7890
    cmd = adb_cmd_factory.setup_reverse_port_forwarding(host_port, device_port)
    cmd.execute()

    # output: host-32 tcp:5678 tcp:7890
    list_cmd = adb_cmd_factory.adb(args=['reverse', '--list'], check_exit_code=True)
    output_lines = list_cmd.execute()

    assert is_in_output(f'tcp:{host_port}', output_lines)
    assert is_in_output(f'tcp:{device_port}', output_lines)


def is_in_output(string_to_match: str, output_lines: List[str]):
    is_match_to_line = map(lambda line: string_to_match in line, output_lines)
    return any(is_match_to_line)
