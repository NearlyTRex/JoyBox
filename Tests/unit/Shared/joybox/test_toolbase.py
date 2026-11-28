# Imports
import pytest

# Local imports
from joybox import config
from joybox import toolbase


###########################################################
# Tool base defaults
#
# A tool that overrides nothing is a nameless no-op whose setup steps succeed.
###########################################################

def test_the_base_tool_has_no_name_or_config():
    tool = toolbase.ToolBase()

    assert tool.get_name() == ""
    assert tool.get_config() == {}


def test_every_base_setup_step_succeeds():
    tool = toolbase.ToolBase()

    assert tool.setup() is True
    assert tool.setup_offline() is True
    assert tool.configure() is True


###########################################################
# Config files and menu launcher
###########################################################

class Named(toolbase.ToolBase):
    NAME = "Thing"


@pytest.fixture
def touched(monkeypatch):
    calls = []
    monkeypatch.setattr(toolbase.environment, "get_tools_root_dir", lambda: "/tools")
    monkeypatch.setattr(toolbase.fileops, "touch_file", lambda src, contents, **kwargs: calls.append((src, contents)) or True)
    return calls


def test_given_config_files_are_written_stripped_under_the_tools_root(touched):
    assert Named().write_config_files(config_files = {"Thing/a.ini": " a \n"}) is True
    assert touched == [("/tools/Thing/a.ini", "a")]


def test_a_tool_writes_its_own_config_files_by_default(touched, monkeypatch):
    monkeypatch.setattr(Named, "get_config_files", lambda self: {"Thing/b.ini": "b"})

    assert Named().write_config_files() is True
    assert touched == [("/tools/Thing/b.ini", "b")]


def test_a_failed_config_file_stops_and_logs(monkeypatch):
    errors = []
    monkeypatch.setattr(toolbase.environment, "get_tools_root_dir", lambda: "/tools")
    monkeypatch.setattr(toolbase.fileops, "touch_file", lambda **kwargs: False)
    monkeypatch.setattr(toolbase.logger, "log_error", errors.append)

    assert Named().write_config_files(config_files = {"a.ini": "a", "b.ini": "b"}) is False
    assert errors == ["Could not setup Thing config files"]


@pytest.mark.parametrize("made, expected, errors", [(True, True, []), (False, False, ["Could not setup the Thing launcher"])])
def test_the_menu_launcher_is_named_after_the_tool(monkeypatch, made, expected, errors):
    launchers = []
    logged = []
    monkeypatch.setattr(toolbase.desktopentry, "set_launcher", lambda **kwargs: launchers.append(kwargs) or made)
    monkeypatch.setattr(toolbase.logger, "log_error", logged.append)

    assert Named().set_menu_launcher(True, "thing.desktop", "Does things", "launch_thing", "icon", config.SetupParams()) is expected
    assert (launchers[0]["name"], launchers[0]["command"], launchers[0]["filename"]) == ("Thing", "launch_thing", "thing.desktop")
    assert logged == errors
