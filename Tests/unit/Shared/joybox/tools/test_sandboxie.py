# Third-party imports
import pytest

# Local imports
from joybox.tools import sandboxie


###########################################################
# Sandboxie config
#
# Every tool's config is gathered whenever any program is looked up, so this
# one must not raise on a Windows machine where Sandboxie is not set up.
###########################################################

PROGRAMS = ["Sandboxie", "SandboxieIni", "SandboxieRpcss", "SandboxieDcomlaunch"]


@pytest.fixture
def windows_settings(monkeypatch):
    values = {
        "sandboxie_exe": "Start.exe",
        "sandboxie_ini_exe": "SbieIni.exe",
        "sandboxie_rpcss_exe": "SandboxieRpcSs.exe",
        "sandboxie_dcomlaunch_exe": "SandboxieDcomLaunch.exe",
        "sandboxie_install_dir": "/sandboxie",
        "sandboxie_sandbox_dir": "/sandbox",
    }
    monkeypatch.setattr(sandboxie.platform_info, "is_sandboxie_platform", lambda: True)
    monkeypatch.setattr(sandboxie.settings, "get_value", lambda section, key, **kwargs: values[key])
    monkeypatch.setattr(sandboxie.settings, "get_path_value", lambda section, key, **kwargs: values[key])
    return values


def test_other_platforms_have_no_config(monkeypatch):
    monkeypatch.setattr(sandboxie.platform_info, "is_sandboxie_platform", lambda: False)

    assert sandboxie.Sandboxie().get_config() == {}


def test_programs_live_in_the_install_dir(windows_settings):
    config = sandboxie.Sandboxie().get_config()

    assert config["Sandboxie"]["program"] == "/sandboxie/Start.exe"
    assert config["Sandboxie"]["sandbox_dir"] == "/sandbox"
    assert config["SandboxieIni"]["program"] == "/sandboxie/SbieIni.exe"
    assert config["SandboxieRpcss"]["program"] == "/sandboxie/SandboxieRpcSs.exe"
    assert config["SandboxieDcomlaunch"]["program"] == "/sandboxie/SandboxieDcomLaunch.exe"


@pytest.mark.parametrize("install_dir", [None, ""])
def test_an_unset_install_dir_leaves_the_programs_unknown(windows_settings, install_dir):
    windows_settings["sandboxie_install_dir"] = install_dir

    config = sandboxie.Sandboxie().get_config()

    assert [config[name]["program"] for name in PROGRAMS] == [None] * 4
