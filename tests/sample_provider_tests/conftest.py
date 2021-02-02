import pytest

from tests.sample_provider_tests.sample_provider_installer import SampleProviderInstaller


@pytest.fixture(scope="session", autouse=True)
def sample_provider(adb_cmd_factory):
    installer = SampleProviderInstaller(adb_cmd_factory)
    installer.install()
    yield installer
    installer.uninstall()
