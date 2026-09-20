# Imports
import pytest

# Local imports
from joybox import chd, config


###########################################################
# CHD wrappers
#
# Each of these builds a chdman argument list. A wrong flag or a swapped input
# and output silently produces the wrong artifact, so the command is what gets
# pinned here; the real round trip lives in the integration suite.
###########################################################

@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(chd.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(chd.programs, "get_tool_program", lambda name: "/tools/chdman")
    return "/tools/chdman"


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(chd.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(chd.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    # The wrappers confirm the artifact landed before reporting success.
    monkeypatch.setattr(chd.os.path, "exists", lambda path: True)


###########################################################
# Companion paths
###########################################################

def test_the_iso_beside_a_chd_swaps_the_extension():
    assert chd.get_disc_iso("/games/Game.chd") == "/games/Game.iso"


def test_the_toc_beside_a_chd_swaps_the_extension():
    assert chd.get_disc_toc("/games/Game.chd") == "/games/Game.toc"


def test_the_companion_paths_stay_in_the_same_directory():
    for accessor in [chd.get_disc_iso, chd.get_disc_toc]:
        assert accessor("/games/psx/Game.chd").startswith("/games/psx/")


def test_the_companion_paths_differ():
    assert chd.get_disc_iso("/games/Game.chd") != chd.get_disc_toc("/games/Game.chd")


def test_a_name_with_spaces_keeps_its_spaces():
    assert chd.get_disc_iso("/games/Final Fantasy VII.chd") == \
        "/games/Final Fantasy VII.iso"


###########################################################
# Creating
###########################################################

def test_creating_invokes_createcd(installed, recording_command, existing_output):
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert recording_command.only()[:2] == ["/tools/chdman", "createcd"]


def test_creating_passes_the_source_as_input(installed, recording_command, existing_output):
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert recording_command.value_after("-i") == "/in/Game.iso"


def test_creating_passes_the_target_as_output(installed, recording_command, existing_output):
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert recording_command.value_after("-o") == "/out/Game.chd"


def test_creating_does_not_swap_input_and_output(installed, recording_command, existing_output):
    # Swapped, chdman would overwrite the source with a compressed empty image.
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert recording_command.value_after("-i") != recording_command.value_after("-o")


def test_creating_blocks_on_the_tool(installed, recording_command, existing_output):
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert "/tools/chdman" in recording_command.options().get_blocking_processes()


def test_creating_declares_its_output_path(installed, recording_command, existing_output):
    # The output path guard is what removes a partial file on interruption.
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")

    assert "/out/Game.chd" in recording_command.options().get_output_paths()


def test_creating_without_the_tool_reports_failure(missing, recording_command):
    assert chd.create_disc_chd("/out/Game.chd", "/in/Game.iso") is False
    assert recording_command.ran() is False


def test_a_failed_create_reports_failure(installed, monkeypatch):
    from fakes import RecordingCommand
    recorder = RecordingCommand(monkeypatch, returncode = 1)

    assert chd.create_disc_chd("/out/Game.chd", "/in/Game.iso") is False


def test_a_failed_create_does_not_delete_the_source(installed, monkeypatch):
    # Deleting the original after a failure loses the only copy.
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the source must not be removed after a failure")

    monkeypatch.setattr(chd.fileops, "remove_file", fail)

    assert chd.create_disc_chd("/out/Game.chd", "/in/Game.iso", delete_original = True) is False


def test_a_successful_create_deletes_the_source_when_asked(installed, recording_command,
                                                           existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(
        chd.fileops, "remove_file", lambda src, **kwargs: removed.append(src))
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso", delete_original = True)

    assert removed == ["/in/Game.iso"]


def test_the_source_is_kept_by_default(installed, recording_command, existing_output,
                                       monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("the source must be kept unless asked for")

    monkeypatch.setattr(chd.fileops, "remove_file", fail)
    chd.create_disc_chd("/out/Game.chd", "/in/Game.iso")


###########################################################
# Extracting
###########################################################

def test_extracting_invokes_extractcd(installed, recording_command, existing_output):
    chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc")

    assert recording_command.only()[:2] == ["/tools/chdman", "extractcd"]


def test_extracting_passes_the_chd_as_input(installed, recording_command, existing_output):
    chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc")

    assert recording_command.value_after("-i") == "/in/Game.chd"


def test_extracting_names_both_outputs(installed, recording_command, existing_output):
    # The toc and the binary are separate outputs; chdman needs both named.
    chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc")

    assert recording_command.value_after("-o") == "/out/Game.toc"
    assert recording_command.value_after("-ob") == "/out/Game.bin"


def test_extracting_without_the_tool_reports_failure(missing, recording_command):
    assert chd.extract_disc_chd("/in/Game.chd", "/out/Game.bin", "/out/Game.toc") is False


###########################################################
# Verifying
###########################################################

def test_verifying_invokes_verify(installed, recording_command, existing_output):
    chd.verify_disc_chd("/in/Game.chd")

    assert recording_command.only()[:2] == ["/tools/chdman", "verify"]


def test_verifying_passes_the_chd_as_input(installed, recording_command, existing_output):
    chd.verify_disc_chd("/in/Game.chd")

    assert recording_command.value_after("-i") == "/in/Game.chd"


def test_verifying_without_the_tool_reports_failure(missing, recording_command):
    assert chd.verify_disc_chd("/in/Game.chd") is False


###########################################################
# Pretending
###########################################################

@pytest.mark.parametrize("call", [
    lambda: chd.create_disc_chd("/out/Game.chd", "/in/Game.iso", pretend_run = True),
    lambda: chd.extract_disc_chd("/in/Game.chd", "/o/Game.bin", "/o/Game.toc", pretend_run = True),
    lambda: chd.verify_disc_chd("/in/Game.chd", pretend_run = True),
])
def test_pretending_still_builds_the_command(installed, recording_command, existing_output, call):
    # The command has to be built so a pretend run can print what it would do.
    call()

    assert recording_command.ran() is True
    assert recording_command.calls[0]["kwargs"].get("pretend_run") is True
