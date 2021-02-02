def test_valid_is_package_installed(device):
    assert device.is_package_installed('com.android.packageinstaller')


def test_invalid_is_package_installed(device):
    assert not device.is_package_installed('not.installed_123')
