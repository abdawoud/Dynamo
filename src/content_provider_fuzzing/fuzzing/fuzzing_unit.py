import logging
from pathlib import Path
from typing import List

from src.content_provider_fuzzing.execution_units.composite_exec_unit import CompositeExecUnit
from src.content_provider_fuzzing.execution_units.execution_unit import ExecutionUnit
from src.content_provider_fuzzing.execution_units.run_android_service_unit import AndroidServiceMetadata, AndroidBundle, \
    RunAndroidServiceUnit
from src.content_provider_fuzzing.fuzzing.fuzzer import Fuzzer, FuzzingSessionResult
from src.content_provider_fuzzing.commands.adb.adb_cmd_factory import AdbCmdFactory
from src.content_provider_fuzzing.execution_units.command_exec_unit import CommandExecUnit
from src.content_provider_fuzzing.server_ipc.zeromq_server import ZeroMqServer


class FuzzingUnit(CompositeExecUnit):

    def __init__(self, adb_cmd_factory: AdbCmdFactory,
                 apk_path: Path,
                 connection_to_fuzzer: ZeroMqServer,
                 fuzzer: Fuzzer):
        self.adb_cmd_factory = adb_cmd_factory
        self.apk_path = apk_path
        self.connection_to_fuzzer = connection_to_fuzzer
        self.fuzzer = fuzzer
        self._logger = logging.getLogger(__name__)

    def get_child_units(self) -> List[ExecutionUnit]:
        return [
            self.connection_to_fuzzer,
            self._create_android_service_unit(),
            self._create_reverse_port_forwarding_unit(),
            self.fuzzer
        ]

    def run(self) -> FuzzingSessionResult:
        fuzzing_results = super().run()[-1]
        return fuzzing_results

    def _setup_reverse_port_forwarding(self):
        setup_reverse_port_forwarding_cmd = self.adb_cmd_factory.setup_reverse_port_forwarding(
            host_port=ZeroMqServer.PORT_NUMBER,
            device_port=ZeroMqServer.PORT_NUMBER)
        setup_reverse_port_forwarding_cmd.execute()

    def _create_reverse_port_forwarding_unit(self) -> ExecutionUnit:
        setup_reverse_port_forwarding_cmd = self.adb_cmd_factory.setup_reverse_port_forwarding(
            host_port=ZeroMqServer.PORT_NUMBER,
            device_port=ZeroMqServer.PORT_NUMBER
        )
        return CommandExecUnit(setup_reverse_port_forwarding_cmd)

    def _create_android_service_unit(self) -> ExecutionUnit:
        service_metadata = AndroidServiceMetadata(
            apk_path=self.apk_path,
            package_name='saarland.cispa.contentproviderfuzzer',
            service_name='saarland.cispa.contentproviderfuzzer/.service.FuzzService',
            bundle=AndroidBundle(int_key_values={'server_port': ZeroMqServer.PORT_NUMBER})
        )
        return RunAndroidServiceUnit(self.adb_cmd_factory, service_metadata)
