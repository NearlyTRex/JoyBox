# Imports
import pytest

# Local imports
from joybox import xbox


###########################################################
# Xbox disc image wrappers
#
# extract-xiso takes its mode as a bare flag and its target directory
# separately, so a misplaced flag extracts into the working directory instead
# of where the caller asked.
###########################################################

@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(xbox.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(xbox.programs, "get_tool_program", lambda name: "/tools/extract-xiso")
    return "/tools/extract-xiso"


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(xbox.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(xbox.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(xbox.os.path, "exists", lambda path: True)


###########################################################
# Extracting
###########################################################

def test_extracting_uses_the_extract_mode(installed, recording_command, existing_output):
    xbox.extract_xbox_iso("/in/Game.iso", "/out")

    assert "-x" in recording_command.only()


def test_extracting_names_the_target_directory(installed, recording_command, existing_output):
    xbox.extract_xbox_iso("/in/Game.iso", "/out")

    assert recording_command.value_after("-d") == "/out"


def test_extracting_passes_the_image_last(installed, recording_command, existing_output):
    # extract-xiso takes the image as a positional after its options.
    xbox.extract_xbox_iso("/in/Game.iso", "/out")

    assert recording_command.only()[-1] == "/in/Game.iso"


def test_extracting_does_not_use_another_mode(installed, recording_command, existing_output):
    cmd = xbox.extract_xbox_iso("/in/Game.iso", "/out") or True
    cmd = recording_command.only()

    assert "-r" not in cmd
    assert "-c" not in cmd


def test_extracting_blocks_on_the_tool(installed, recording_command, existing_output):
    xbox.extract_xbox_iso("/in/Game.iso", "/out")

    assert "/tools/extract-xiso" in recording_command.options().get_blocking_processes()


def test_extracting_without_the_tool_reports_failure(missing, recording_command):
    assert xbox.extract_xbox_iso("/in/Game.iso", "/out") is False
    assert recording_command.ran() is False


def test_a_failed_extract_reports_failure(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert xbox.extract_xbox_iso("/in/Game.iso", "/out") is False


def test_a_failed_extract_does_not_delete_the_image(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the image must not be removed after a failure")

    monkeypatch.setattr(xbox.fileops, "remove_file", fail)

    assert xbox.extract_xbox_iso("/in/Game.iso", "/out", delete_original = True) is False


def test_a_successful_extract_deletes_the_image_when_asked(installed, recording_command,
                                                           existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(
        xbox.fileops, "remove_file", lambda src, **kwargs: removed.append(src))
    xbox.extract_xbox_iso("/in/Game.iso", "/out", delete_original = True)

    assert removed == ["/in/Game.iso"]


def test_the_image_is_kept_by_default(installed, recording_command, existing_output,
                                      monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("the image must be kept unless asked for")

    monkeypatch.setattr(xbox.fileops, "remove_file", fail)
    xbox.extract_xbox_iso("/in/Game.iso", "/out")


###########################################################
# Rewriting
###########################################################

def test_rewriting_uses_the_rewrite_mode(installed, recording_command):
    xbox.rewrite_xbox_iso("/games/Game.iso")

    assert "-r" in recording_command.only()


def test_rewriting_targets_the_images_own_directory(installed, recording_command):
    # A rewrite replaces the image in place, so the output has to land beside
    # it rather than in the working directory.
    xbox.rewrite_xbox_iso("/games/xbox/Game.iso")

    assert recording_command.value_after("-d") == "/games/xbox"


def test_rewriting_passes_the_image_last(installed, recording_command):
    xbox.rewrite_xbox_iso("/games/Game.iso")

    assert recording_command.only()[-1] == "/games/Game.iso"


def test_rewriting_keeps_the_original_by_default(installed, recording_command):
    # Without -D extract-xiso leaves a .old backup beside the new image.
    xbox.rewrite_xbox_iso("/games/Game.iso")

    assert "-D" not in recording_command.only()


def test_rewriting_can_discard_the_original(installed, recording_command):
    xbox.rewrite_xbox_iso("/games/Game.iso", delete_original = True)

    assert "-D" in recording_command.only()


def test_the_discard_flag_precedes_the_image(installed, recording_command):
    # Options after the positional are not parsed as options.
    xbox.rewrite_xbox_iso("/games/Game.iso", delete_original = True)
    cmd = recording_command.only()

    assert cmd.index("-D") < cmd.index("/games/Game.iso")


def test_rewriting_without_the_tool_reports_failure(missing, recording_command):
    assert xbox.rewrite_xbox_iso("/games/Game.iso") is False
    assert recording_command.ran() is False


def test_a_failed_rewrite_reports_failure(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert xbox.rewrite_xbox_iso("/games/Game.iso") is False


###########################################################
# Pretending
###########################################################

@pytest.mark.parametrize("call", [
    lambda: xbox.extract_xbox_iso("/in/Game.iso", "/out", pretend_run = True),
    lambda: xbox.rewrite_xbox_iso("/games/Game.iso", pretend_run = True),
])
def test_pretending_still_builds_the_command(installed, recording_command,
                                             existing_output, call):
    call()

    assert recording_command.calls[0]["kwargs"].get("pretend_run") is True
