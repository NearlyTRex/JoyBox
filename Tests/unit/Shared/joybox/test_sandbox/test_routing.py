# Imports
import getpass
import os
import pytest

# Local imports
from joybox import commandoptions, config, sandbox
from sandbox_helpers import options, WINE, SANDBOXIE, NEITHER, PREFIX


###########################################################
# Routing a command through a prefix
#
# Wine and Sandboxie each only exist on one platform, and a command that is
# routed through the wrong one, or through none at all, runs against the real
# machine rather than inside the prefix.
###########################################################

GAME_EXE = "/games/cache/Game/Game.exe"


@pytest.fixture
def installed_runners(monkeypatch):
    # Neither runner is installed on the machine running the tests, and the
    # lookup raises rather than returning nothing.
    monkeypatch.setattr(sandbox, "get_wine_command", lambda: "/tools/wine")
    monkeypatch.setattr(sandbox, "get_sandboxie_command", lambda: "/tools/start.exe")


@pytest.fixture
def linux(monkeypatch, installed_runners):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: True)
    monkeypatch.setattr(sandbox.platform_info, "is_sandboxie_platform", lambda: False)


@pytest.fixture
def windows(monkeypatch, installed_runners):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: False)
    monkeypatch.setattr(sandbox.platform_info, "is_sandboxie_platform", lambda: True)


@pytest.fixture
def cached_game(monkeypatch):
    monkeypatch.setattr(sandbox.commandbase, "is_windows_executable_command", lambda cmd: True)
    monkeypatch.setattr(sandbox.commandbase, "is_cached_game_command", lambda cmd: True)
    monkeypatch.setattr(sandbox.commandbase, "is_local_sandboxed_program_command", lambda cmd: False)


def test_a_cached_game_runs_via_wine_on_linux(linux, cached_game):
    assert sandbox.should_be_run_via_wine(GAME_EXE) is True


def test_a_cached_game_does_not_run_via_wine_on_windows(windows, cached_game):
    assert sandbox.should_be_run_via_wine(GAME_EXE) is False


def test_a_cached_game_runs_via_sandboxie_on_windows(windows, cached_game):
    assert sandbox.should_be_run_via_sandboxie(GAME_EXE) is True


def test_a_cached_game_does_not_run_via_sandboxie_on_linux(linux, cached_game):
    assert sandbox.should_be_run_via_sandboxie(GAME_EXE) is False


def test_a_native_program_is_not_routed_through_wine(linux, monkeypatch):
    monkeypatch.setattr(sandbox.commandbase, "is_windows_executable_command", lambda cmd: False)

    assert sandbox.should_be_run_via_wine("/usr/bin/true") is False


def test_a_sandboxed_local_program_runs_via_wine(linux, monkeypatch):
    monkeypatch.setattr(sandbox.commandbase, "is_windows_executable_command", lambda cmd: True)
    monkeypatch.setattr(sandbox.commandbase, "is_cached_game_command", lambda cmd: False)
    monkeypatch.setattr(sandbox.commandbase, "is_local_sandboxed_program_command", lambda cmd: True)

    assert sandbox.should_be_run_via_wine(GAME_EXE) is True


def test_an_unsandboxed_windows_program_is_left_alone(linux, monkeypatch):
    monkeypatch.setattr(sandbox.commandbase, "is_windows_executable_command", lambda cmd: True)
    monkeypatch.setattr(sandbox.commandbase, "is_cached_game_command", lambda cmd: False)
    monkeypatch.setattr(sandbox.commandbase, "is_local_sandboxed_program_command", lambda cmd: False)

    assert sandbox.should_be_run_via_wine(GAME_EXE) is False


def test_a_command_already_running_under_wine_is_not_wrapped_again(linux, cached_game):
    # Wrapping twice starts wine inside wine, which never launches the game.
    assert sandbox.should_be_run_via_wine(["/tools/wine", GAME_EXE]) is False


def test_a_command_already_running_under_sandboxie_is_not_wrapped_again(windows, cached_game):
    assert sandbox.should_be_run_via_sandboxie(["/tools/start.exe", GAME_EXE]) is False
