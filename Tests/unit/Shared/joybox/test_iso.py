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

@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(iso.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: "/tools/xorriso")
    return "/tools/xorriso"


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(iso.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(iso.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def existing_output(monkeypatch):
    monkeypatch.setattr(iso.os.path, "exists", lambda path: True)


@pytest.fixture
def no_archive_fallback(monkeypatch):
    # extract_iso tries the archive path first; force it to the tool path.
    monkeypatch.setattr(iso.archive, "extract_archive", lambda **kwargs: False)


@pytest.fixture
def source_image(tmp_path):
    # extract_iso refuses a source that is not there, so it has to exist.
    target = tmp_path / "Game.iso"
    target.write_bytes(b"x")
    return str(target)


@pytest.fixture
def populated_output(monkeypatch):
    monkeypatch.setattr(iso.paths, "does_directory_contain_files", lambda path, **kwargs: True)


###########################################################
# Creating
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


###########################################################
# Extracting
###########################################################

def test_the_archive_path_is_tried_first(installed, monkeypatch, recording_command,
                                         source_image):
    # 7z reads an iso directly and is faster; xorriso is the fallback.
    monkeypatch.setattr(iso.archive, "extract_archive", lambda **kwargs: True)

    assert iso.extract_iso(source_image, "/out") is True
    assert recording_command.ran() is False


def test_extracting_falls_back_to_the_tool(installed, recording_command,
                                           populated_output, no_archive_fallback,
                                           source_image):
    iso.extract_iso(source_image, "/out")

    assert recording_command.ran() is True
    assert recording_command.value_after("-indev") == source_image


def test_extracting_enables_the_extraction_mode(installed, recording_command,
                                                populated_output, no_archive_fallback,
                                                source_image):
    iso.extract_iso(source_image, "/out")

    assert recording_command.value_after("-osirrox") == "on"


def test_extracting_takes_the_whole_image(installed, recording_command,
                                          populated_output, no_archive_fallback,
                                          source_image):
    iso.extract_iso(source_image, "/out")

    assert recording_command.value_after("-extract") == "/"


def test_extracting_names_the_target_directory(installed, recording_command,
                                               populated_output, no_archive_fallback,
                                               source_image):
    iso.extract_iso(source_image, "/out")
    cmd = recording_command.only()

    assert cmd[cmd.index("-extract") + 2] == "/out"


def test_extracting_without_the_tool_reports_failure(missing, recording_command,
                                                     no_archive_fallback, source_image):
    assert iso.extract_iso(source_image, "/out") is False


def test_extracting_a_missing_image_reports_failure(installed, recording_command,
                                                    no_archive_fallback, tmp_path):
    # xorriso writes an empty directory and exits 0 for a source that is not an
    # iso, so the source is checked before it runs.
    assert iso.extract_iso(str(tmp_path / "absent.iso"), "/out") is False
    assert recording_command.ran() is False


def test_an_empty_extraction_reports_failure(installed, recording_command,
                                             no_archive_fallback, source_image,
                                             monkeypatch):
    monkeypatch.setattr(iso.paths, "does_directory_contain_files", lambda path, **kwargs: False)

    assert iso.extract_iso(source_image, "/out") is False


###########################################################
# Mount state
###########################################################

def test_a_missing_image_is_not_mounted(tmp_path):
    assert iso.is_iso_mounted(str(tmp_path / "absent.iso"), str(tmp_path)) is False


def test_an_empty_mount_directory_is_not_mounted(tmp_path):
    # An empty directory is the failed-mount signature.
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")
    mount = tmp_path / "mnt"
    mount.mkdir()

    assert iso.is_iso_mounted(str(image), str(mount)) is False


def test_a_populated_mount_directory_is_mounted(tmp_path):
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")
    mount = tmp_path / "mnt"
    mount.mkdir()
    (mount / "file.txt").write_text("content")

    assert iso.is_iso_mounted(str(image), str(mount)) is True


def test_a_missing_mount_directory_is_not_mounted(tmp_path):
    image = tmp_path / "Game.iso"
    image.write_bytes(b"x")

    assert iso.is_iso_mounted(str(image), str(tmp_path / "absent")) is False
