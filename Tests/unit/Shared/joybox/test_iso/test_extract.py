# Imports
import pytest

# Local imports
from joybox import iso


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


def test_a_failed_extraction_reports_failure(installed, monkeypatch, no_archive_fallback,
                                             populated_output, source_image):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert iso.extract_iso(source_image, "/out") is False


def test_extracted_files_are_made_writable(installed, recording_command, monkeypatch,
                                           no_archive_fallback, populated_output,
                                           source_image):
    # xorriso keeps the read only modes of the disc.
    calls = []
    monkeypatch.setattr(
        iso.fileops, "chmod_file_or_directory", lambda **kwargs: calls.append(kwargs))

    assert iso.extract_iso(source_image, "/out") is True
    assert calls[0]["src"] == "/out"
    assert (calls[0]["perms"], calls[0]["dperms"]) == (666, 777)


def test_a_tool_extraction_can_delete_the_source(installed, recording_command, monkeypatch,
                                                 no_archive_fallback, populated_output,
                                                 source_image, tmp_path):
    monkeypatch.setattr(iso.fileops, "chmod_file_or_directory", lambda **kwargs: True)

    assert iso.extract_iso(source_image, str(tmp_path / "out"), delete_original = True) is True
    assert not iso.os.path.exists(source_image)


###########################################################
# Extracting a tree to rebuild from
###########################################################

@pytest.fixture
def no_chmod(monkeypatch):
    calls = []
    monkeypatch.setattr(
        iso.fileops, "chmod_file_or_directory", lambda **kwargs: calls.append(kwargs) or True)
    return calls


def test_a_tree_is_extracted_with_the_tool(installed, recording_command, no_chmod,
                                           source_image, tmp_path):
    target = tmp_path / "tree"

    assert iso.extract_buildable_iso_tree(source_image, str(target)) is True
    assert target.is_dir()
    assert recording_command.value_after("-indev") == source_image
    assert recording_command.only()[-1] == str(target)


def test_a_tree_is_left_writable_but_not_executable(installed, recording_command, no_chmod,
                                                    source_image, tmp_path):
    iso.extract_buildable_iso_tree(source_image, str(tmp_path / "tree"))

    assert (no_chmod[0]["perms"], no_chmod[0]["dperms"]) == (644, 755)


def test_a_tree_from_a_missing_image_is_refused(installed, recording_command, tmp_path):
    assert iso.extract_buildable_iso_tree(str(tmp_path / "absent.iso"), str(tmp_path)) is False
    assert recording_command.ran() is False


def test_a_tree_without_the_tool_is_refused(missing, recording_command, source_image, tmp_path):
    assert iso.extract_buildable_iso_tree(source_image, str(tmp_path / "tree")) is False
    assert recording_command.ran() is False


def test_a_tree_without_a_destination_is_refused(installed, recording_command, monkeypatch,
                                                 source_image, tmp_path):
    monkeypatch.setattr(iso.fileops, "make_directory", lambda **kwargs: False)

    assert iso.extract_buildable_iso_tree(source_image, str(tmp_path / "tree")) is False
    assert recording_command.ran() is False


def test_a_failed_tree_extraction_is_reported(installed, monkeypatch, no_chmod,
                                              source_image, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert iso.extract_buildable_iso_tree(source_image, str(tmp_path / "tree")) is False
    assert no_chmod == []
