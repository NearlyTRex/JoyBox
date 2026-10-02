# Imports
import pytest

# Local imports
from joybox import iso


###########################################################
# ISO wrappers
#
# Each builds a xorriso argument list. The flags decide whether long filenames
# and deep paths survive, so they are pinned here; the real round trip lives in
# the integration suite.
###########################################################

def test_creating_runs_in_mkisofs_mode(installed, recording_command, existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert "-as" in recording_command.only()
    assert recording_command.value_after("-as") == "mkisofs"


def test_creating_names_the_output(installed, recording_command, existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert recording_command.value_after("-o") == "/out/Game.iso"


def test_creating_passes_the_source_directory(installed, recording_command,
                                              existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert str(tmp_path) in recording_command.only()


def test_creating_uses_iso_level_three(installed, recording_command, existing_output, tmp_path):
    # Level 1 caps filenames at 8.3 and files at 2 GB, which no disc image
    # survives.
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert recording_command.value_after("-iso-level") == "3"


@pytest.mark.parametrize("flag", ["-graft-points", "-full-iso9660-filenames", "-joliet"])
def test_creating_keeps_long_names(installed, recording_command, existing_output, tmp_path, flag):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert flag in recording_command.only()


def test_a_volume_name_is_passed(installed, recording_command, existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path), volume_name = "GAME_DISC")

    assert recording_command.value_after("-volid") == "GAME_DISC"


def test_no_volume_name_leaves_the_flag_out(installed, recording_command,
                                            existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert "-volid" not in recording_command.only()


def test_extra_source_directories_reach_the_command(installed, recording_command,
                                                    existing_output, tmp_path):
    # Declared but unreachable, these produced an empty iso that still reported
    # success.
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    iso.create_iso("/out/Game.iso", source_dirs = [str(first), str(second)])

    assert str(first) in recording_command.only()
    assert str(second) in recording_command.only()


def test_a_source_dir_and_extra_dirs_are_all_passed(installed, recording_command,
                                                    existing_output, tmp_path):
    main = tmp_path / "main"
    extra = tmp_path / "extra"
    main.mkdir()
    extra.mkdir()
    iso.create_iso("/out/Game.iso", source_dir = str(main), source_dirs = [str(extra)])

    assert str(main) in recording_command.only()
    assert str(extra) in recording_command.only()


def test_creating_without_the_tool_reports_failure(missing, recording_command, tmp_path):
    assert iso.create_iso("/out/Game.iso", source_dir = str(tmp_path)) is False
    assert recording_command.ran() is False


def test_creating_declares_its_output_path(installed, recording_command,
                                           existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dir = str(tmp_path))

    assert "/out/Game.iso" in recording_command.options().get_output_paths()


def test_a_failed_create_does_not_delete_the_source(installed, monkeypatch, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the source must not be removed after a failure")

    monkeypatch.setattr(iso.fileops, "remove_directory", fail)

    assert iso.create_iso("/out/Game.iso", source_dir = str(tmp_path),
                          delete_original = True) is False


def test_an_invalid_extra_source_directory_is_skipped(installed, recording_command,
                                                      existing_output, tmp_path):
    iso.create_iso("/out/Game.iso", source_dirs = [None, str(tmp_path)])

    assert None not in recording_command.only()
    assert str(tmp_path) in recording_command.only()


def test_a_successful_create_can_delete_the_source(installed, recording_command, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")

    assert iso.create_iso(str(image), source_dir = str(source), delete_original = True) is True
    assert not source.exists()


def test_a_successful_create_keeps_the_source_by_default(installed, recording_command, tmp_path):
    source = tmp_path / "tree"
    source.mkdir()
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")

    assert iso.create_iso(str(image), source_dir = str(source)) is True
    assert source.exists()


def test_a_create_that_writes_nothing_reports_failure(installed, recording_command, tmp_path):
    assert iso.create_iso(str(tmp_path / "Game.iso"), source_dir = str(tmp_path)) is False
