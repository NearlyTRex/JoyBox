# Imports
import sys

# Third-party imports
import pytest

# Local imports
from joybox import system
from joybox.cli import setup_game_emulators


###########################################################
# Package selection
#
# Names are matched exactly, so a misspelled one would otherwise install
# nothing and still report success.
###########################################################

class FakePackage:

    def __init__(self, name):
        self.name = name

    def get_name(self):
        return self.name


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    state = {"installed": [], "result": True, "errors": []}
    monkeypatch.setattr(setup_game_emulators.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(setup_game_emulators.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(setup_game_emulators.programs, "get_emulators", lambda: [FakePackage("Alpha"), FakePackage("Beta")])

    def install(**kwargs):
        state["installed"].append(kwargs["packages"])
        return state["result"]

    monkeypatch.setattr(setup_game_emulators.setup, "setup_emulators", install)
    log_error = setup_game_emulators.logger.log_error

    def record_error(message, **kwargs):
        state["errors"].append(message)
        log_error(message, **kwargs)

    monkeypatch.setattr(setup_game_emulators.logger, "log_error", record_error)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["setup_game_emulators", *extra])
        return system.run_main(setup_game_emulators.main)

    state["run"] = run
    return state


def test_without_a_selection_everything_is_installed(tool):
    tool["run"]()

    assert tool["installed"] == [None]


def test_selected_packages_are_passed_through(tool):
    tool["run"]("-k", "Beta, Alpha,")

    assert tool["installed"] == [["Beta", "Alpha"]]


def test_an_unknown_package_stops_before_installing(tool):
    with pytest.raises(SystemExit) as raised:
        tool["run"]("-k", "Alpha,alpha,Gamma")
    assert raised.value.code != 0
    assert tool["errors"] == ["Unknown emulator packages: alpha, Gamma"]
    assert tool["installed"] == []


def test_a_failed_install_exits_with_an_error(tool):
    tool["result"] = False

    with pytest.raises(SystemExit) as raised:
        tool["run"]("-k", "Alpha")
    assert raised.value.code != 0
    assert tool["errors"] == ["Setup of emulators failed"]
