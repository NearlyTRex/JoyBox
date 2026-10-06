# Imports
import pytest

# Local imports
from joybox import playstation


###########################################################
# PSN packages
###########################################################

def test_extracting_a_package_names_the_content_directory(installed, recording_command, existing_output):
    playstation.extract_psn_pkg("/in/Game.pkg", "/out")

    assert recording_command.value_after("--content") == "/out"


def test_extracting_a_package_runs_the_script_under_the_venv(installed, recording_command, existing_output):
    # The script is not executable on its own; it is handed to the interpreter.
    playstation.extract_psn_pkg("/in/Game.pkg", "/out")

    assert recording_command.only()[:2] == ["/tools/venv/python", "/tools/psngetpkginfo.py"]


def test_extracting_a_package_passes_it_last(installed, recording_command, existing_output):
    playstation.extract_psn_pkg("/in/Game.pkg", "/out")

    assert recording_command.only()[-1] == "/in/Game.pkg"


def test_extracting_a_package_without_the_tool_reports_failure(missing, recording_command):
    assert playstation.extract_psn_pkg("/in/Game.pkg", "/out") is False
    assert recording_command.ran() is False


def test_extracting_a_package_without_the_script_reports_failure(venv_only, recording_command):
    assert playstation.extract_psn_pkg("/in/Game.pkg", "/out") is False
    assert recording_command.ran() is False


def test_a_failed_package_extract_reports_failure(installed, monkeypatch):
    # A run that was not told to exit carries on to the next package.
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert playstation.extract_psn_pkg("/in/Game.pkg", "/out") is False


def test_a_failed_package_extract_can_quit_the_program(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    with pytest.raises(SystemExit):
        playstation.extract_psn_pkg("/in/Game.pkg", "/out", exit_on_failure = True)


def test_extracting_a_package_can_remove_it(installed, recording_command, existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(playstation.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    playstation.extract_psn_pkg("/in/Game.pkg", "/out", delete_original = True)

    assert removed == ["/in/Game.pkg"]


###########################################################
# PSN package information
###########################################################

INFO_OUTPUT = "\n".join([
    "NPS Type: PSV GAME",
    "Title ID: PCSE00123",
    "Title: A Game",
    "Region: USA",
    "Content ID: UP0001-PCSE00123_00-0000000000000000",
    "Content Type: 21",
    "DRM Type: 3",
    "Min FW: 3.60",
    "Version: 1.00",
    "App Ver: 1.01",
    "Size: 123456",
])


def info_command(monkeypatch, output):
    from fakes import RecordingCommand
    return RecordingCommand(monkeypatch, output = output)


def test_every_known_field_is_parsed(installed, monkeypatch):
    info_command(monkeypatch, INFO_OUTPUT)

    info = playstation.get_psn_package_info("/in/Game.pkg")

    assert info == {
        "nps_type": "PSV GAME",
        "title_id": "PCSE00123",
        "title": "A Game",
        "region": "USA",
        "content_id": "UP0001-PCSE00123_00-0000000000000000",
        "content_type": "21",
        "drm_type": "3",
        "min_fw": "3.60",
        "version": "1.00",
        "app_ver": "1.01",
        "size": "123456",
    }


def test_a_value_containing_a_colon_is_kept_whole(installed, monkeypatch):
    # Subtitled titles are commonplace, and splitting on every colon truncates
    # the name at the first one.
    info_command(monkeypatch, "Title: Ratchet & Clank: Up Your Arsenal")

    assert playstation.get_psn_package_info("/in/Game.pkg")["title"] == \
        "Ratchet & Clank: Up Your Arsenal"


def test_an_unknown_field_is_ignored(installed, monkeypatch):
    info_command(monkeypatch, "Something Else: value")

    assert playstation.get_psn_package_info("/in/Game.pkg") == {}


def test_a_line_without_a_field_is_ignored(installed, monkeypatch):
    info_command(monkeypatch, "just a banner line\nTitle: A Game")

    assert playstation.get_psn_package_info("/in/Game.pkg") == {"title": "A Game"}


def test_no_output_yields_nothing(installed, monkeypatch):
    info_command(monkeypatch, "")

    assert playstation.get_psn_package_info("/in/Game.pkg") is None


def test_package_info_without_the_tool_yields_nothing(missing, recording_command):
    assert playstation.get_psn_package_info("/in/Game.pkg") is None
    assert recording_command.ran() is False


def test_package_info_without_the_script_yields_nothing(venv_only, recording_command):
    assert playstation.get_psn_package_info("/in/Game.pkg") is None
    assert recording_command.ran() is False
