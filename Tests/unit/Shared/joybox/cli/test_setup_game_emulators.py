# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
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
    harness = CommandHarness(monkeypatch, setup_game_emulators)
    harness.installed = []
    harness.result = True
    monkeypatch.setattr(setup_game_emulators.programs, "get_emulators", lambda: [FakePackage("Alpha"), FakePackage("Beta")])

    def install(**kwargs):
        harness.installed.append(kwargs["packages"])
        return harness.result

    monkeypatch.setattr(setup_game_emulators.setup, "setup_emulators", install)
    return harness


def test_without_a_selection_everything_is_installed(tool):
    tool.run()

    assert tool.installed == [None]


def test_selected_packages_are_passed_through(tool):
    tool.run("-k", "Beta, Alpha,")

    assert tool.installed == [["Beta", "Alpha"]]


def test_an_unknown_package_stops_before_installing(tool):
    assert tool.exit_code("-k", "Alpha,alpha,Gamma") != 0
    assert tool.errors == ["Unknown emulator packages: alpha, Gamma"]
    assert tool.installed == []


def test_a_failed_install_exits_with_an_error(tool):
    tool.result = False

    assert tool.exit_code("-k", "Alpha") != 0
    assert tool.errors == ["Setup of emulators failed"]


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, setup_game_emulators)
