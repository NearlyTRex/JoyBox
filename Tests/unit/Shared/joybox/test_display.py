# Third-party imports
import pytest

# Local imports
from joybox import command
from joybox import display
from joybox import programs


###########################################################
# Screen resolution
#
# Games that change the resolution are followed by a restore to the configured
# default, which must not fire a NirCmd run when nothing changed.
###########################################################

DEFAULT_W = 1920
DEFAULT_H = 1080
DEFAULT_C = 32


@pytest.fixture
def nircmd_runs(monkeypatch):
    runs = []
    monkeypatch.setattr(programs, "is_tool_installed", lambda name: name == "NirCmd")
    monkeypatch.setattr(programs, "get_tool_program", lambda name: "nircmd.exe")
    monkeypatch.setattr(command, "run_returncode_command", lambda **kwargs: runs.append(kwargs) or 0)
    return runs


@pytest.fixture
def default_resolution(isolated_settings):
    isolated_settings.set_value("UserData.Resolution", "screen_resolution_w", str(DEFAULT_W))
    isolated_settings.set_value("UserData.Resolution", "screen_resolution_h", str(DEFAULT_H))
    isolated_settings.set_value("UserData.Resolution", "screen_resolution_c", str(DEFAULT_C))


def test_setting_the_resolution_runs_nircmd(nircmd_runs):
    assert display.set_screen_resolution(1280, 720, 16, pretend_run = True)
    assert nircmd_runs[0]["cmd"] == ["nircmd.exe", "setdisplay", "1280", "720", "16"]
    assert nircmd_runs[0]["pretend_run"] is True
    assert nircmd_runs[0]["options"].is_shell()


def test_setting_the_resolution_without_nircmd_fails(monkeypatch):
    monkeypatch.setattr(programs, "is_tool_installed", lambda name: False)
    assert display.set_screen_resolution(1280, 720, 16) is False


def test_restoring_at_the_default_resolution_does_nothing(default_resolution, monkeypatch, nircmd_runs):
    monkeypatch.setattr(display.gui, "get_current_screen_resolution", lambda: (DEFAULT_W, DEFAULT_H))
    assert display.restore_default_screen_resolution()
    assert nircmd_runs == []


def test_restoring_from_another_resolution_sets_the_default(default_resolution, monkeypatch, nircmd_runs):
    monkeypatch.setattr(display.gui, "get_current_screen_resolution", lambda: (1280, 720))
    assert display.restore_default_screen_resolution()
    assert nircmd_runs[0]["cmd"] == ["nircmd.exe", "setdisplay", str(DEFAULT_W), str(DEFAULT_H), str(DEFAULT_C)]
