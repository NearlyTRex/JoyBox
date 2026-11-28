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


@pytest.fixture
def nircmd_exit(monkeypatch):
    exit_code = {"code": 0}
    errors = []
    monkeypatch.setattr(programs, "is_tool_installed", lambda name: name == "NirCmd")
    monkeypatch.setattr(programs, "get_tool_program", lambda name: "nircmd.exe")
    monkeypatch.setattr(command, "run_returncode_command", lambda **kwargs: exit_code["code"])
    monkeypatch.setattr(
        display.logger, "log_error",
        lambda message, quit_program = False: errors.append((message, quit_program)))
    exit_code["errors"] = errors
    return exit_code


def test_a_nircmd_success_sets_the_resolution(nircmd_exit):
    assert display.set_screen_resolution(1280, 720, 16) is True
    assert nircmd_exit["errors"] == []


def test_a_nircmd_failure_fails_quietly(nircmd_exit):
    nircmd_exit["code"] = 1

    assert display.set_screen_resolution(1280, 720, 16) is False
    assert nircmd_exit["errors"] == []


@pytest.mark.parametrize("verbose,exit_on_failure", [(True, False), (False, True)])
def test_a_nircmd_failure_is_reported_when_asked(nircmd_exit, verbose, exit_on_failure):
    nircmd_exit["code"] = 3

    assert display.set_screen_resolution(1280, 720, 16, verbose = verbose, exit_on_failure = exit_on_failure) is False
    message, quit_program = nircmd_exit["errors"][0]
    assert "code 3" in message
    assert quit_program is exit_on_failure


def test_a_nircmd_failure_fails_the_restore(default_resolution, monkeypatch, nircmd_exit):
    nircmd_exit["code"] = 1
    monkeypatch.setattr(display.gui, "get_current_screen_resolution", lambda: (1280, 720))

    assert display.restore_default_screen_resolution() is False
