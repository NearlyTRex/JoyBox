# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.nintendo import threeds
from joybox import filebulk


###########################################################
# 3DS conversion
###########################################################

def test_converting_a_cia_to_a_cci_uses_its_own_mode(installed, recording_command, existing_output):
    threeds.convert_3ds_cia_to_cci("/in/Game.cia", "/out/Game.cci")

    assert recording_command.only() == \
        ["/tools/makerom", "-ciatocci", "/in/Game.cia", "-o", "/out/Game.cci"]


def test_converting_a_cci_to_a_cia_uses_its_own_mode(installed, recording_command, existing_output):
    # The two modes differ by one token and swapping them writes a file the
    # emulator cannot read.
    threeds.convert_3ds_cci_to_cia("/in/Game.cci", "/out/Game.cia")

    assert recording_command.only() == \
        ["/tools/makerom", "-ccitocia", "/in/Game.cci", "-o", "/out/Game.cia"]


@pytest.mark.parametrize("wrapper", [
    threeds.convert_3ds_cia_to_cci,
    threeds.convert_3ds_cci_to_cia,
])
def test_a_conversion_without_its_tool_reports_failure(missing, recording_command, wrapper):
    assert wrapper("/in/Game.cia", "/out/Game.cci") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [
    threeds.convert_3ds_cia_to_cci,
    threeds.convert_3ds_cci_to_cia,
])
def test_a_failed_conversion_reports_failure(installed, monkeypatch, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert wrapper("/in/Game.cia", "/out/Game.cci") is False


@pytest.mark.parametrize("wrapper", [
    threeds.convert_3ds_cia_to_cci,
    threeds.convert_3ds_cci_to_cia,
])
def test_a_conversion_that_writes_nothing_reports_failure(installed, recording_command, tmp_path, wrapper):
    # makerom can return zero and produce no file.
    assert wrapper("/in/Game.cia", str(tmp_path / "absent.cci")) is False


###########################################################
# 3DS trimming
###########################################################

def test_trimming_a_cci_uses_the_trim_flag(installed, recording_command, scratch, existing_output):
    threeds.trim_3ds_cci("/in/Game.3ds", "/out/Game.3ds")

    assert recording_command.only() == \
        ["/tools/3dsromtool", "--trim", os.path.join(scratch, "temp.3ds")]


def test_untrimming_a_cci_uses_the_restore_flag(installed, recording_command, scratch, existing_output):
    threeds.untrim_3ds_cci("/in/Game.3ds", "/out/Game.3ds")

    assert recording_command.only() == \
        ["/tools/3dsromtool", "--restore", os.path.join(scratch, "temp.3ds")]


@pytest.mark.parametrize("wrapper", [threeds.trim_3ds_cci, threeds.untrim_3ds_cci])
def test_trimming_works_on_a_copy(installed, recording_command, scratch, existing_output, monkeypatch, wrapper):
    # The tool edits its input in place, so the original must not be handed to
    # it directly.
    copies = []
    monkeypatch.setattr(
        threeds.fileops, "copy_file_or_directory",
        lambda src, dest, **kwargs: copies.append((src, dest)))

    wrapper("/in/Game.3ds", "/out/Game.3ds")

    assert copies == [("/in/Game.3ds", os.path.join(scratch, "temp.3ds"))]


@pytest.mark.parametrize("wrapper", [threeds.trim_3ds_cci, threeds.untrim_3ds_cci])
def test_the_trimmed_copy_is_moved_to_the_destination(installed, recording_command, scratch, existing_output, monkeypatch, wrapper):
    moves = []
    monkeypatch.setattr(
        threeds.fileops, "move_file_or_directory",
        lambda src, dest, **kwargs: moves.append((src, dest)))

    wrapper("/in/Game.3ds", "/out/Game.3ds")

    assert moves == [(os.path.join(scratch, "temp.3ds"), "/out/Game.3ds")]


@pytest.mark.parametrize("wrapper", [threeds.trim_3ds_cci, threeds.untrim_3ds_cci])
def test_trimming_without_its_tool_reports_failure(missing, recording_command, wrapper):
    assert wrapper("/in/Game.3ds", "/out/Game.3ds") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [threeds.trim_3ds_cci, threeds.untrim_3ds_cci])
def test_trimming_without_a_scratch_directory_reports_failure(installed, recording_command, no_scratch, wrapper):
    assert wrapper("/in/Game.3ds", "/out/Game.3ds") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [threeds.trim_3ds_cci, threeds.untrim_3ds_cci])
def test_a_failed_trim_does_not_move_anything(installed, monkeypatch, scratch, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("a failed trim must not overwrite the destination")

    monkeypatch.setattr(threeds.fileops, "move_file_or_directory", fail)

    assert wrapper("/in/Game.3ds", "/out/Game.3ds") is False


###########################################################
# 3DS extraction
###########################################################

def test_extracting_a_cia_names_every_output(installed, recording_command, scratch, existing_output, monkeypatch):
    monkeypatch.setattr(threeds.paths, "get_directory_contents", lambda path: [])
    monkeypatch.setattr(threeds.paths, "is_directory_empty", lambda path: False)
    monkeypatch.setattr(filebulk, "move_contents", lambda **kwargs: True)

    threeds.extract_3ds_cia("/in/Game.cia", "/out")
    cmd = recording_command.only()

    assert cmd[0] == "/tools/ctrtool"
    assert recording_command.value_after("--certs") == os.path.join(scratch, "00000000.cer")
    assert recording_command.value_after("--tik") == os.path.join(scratch, "00000000.tik")
    assert recording_command.value_after("--tmd") == os.path.join(scratch, "00000000.tmd")
    assert cmd[-1] == "/in/Game.cia"


def test_extracted_contents_are_renamed_to_app_files(installed, recording_command, scratch, existing_output, monkeypatch):
    # ctrtool writes contents.0000, and the emulator expects 0000.app.
    moves = []
    monkeypatch.setattr(threeds.paths, "get_directory_contents", lambda path: ["contents.0000", "00000000.tik"])
    monkeypatch.setattr(threeds.paths, "is_directory_empty", lambda path: False)
    monkeypatch.setattr(filebulk, "move_contents", lambda **kwargs: True)
    monkeypatch.setattr(
        threeds.fileops, "move_file_or_directory",
        lambda src, dest, **kwargs: moves.append((src, dest)))

    threeds.extract_3ds_cia("/in/Game.cia", "/out")

    assert moves == [(os.path.join(scratch, "contents.0000"), os.path.join(scratch, "0000.app"))]


def test_extracting_a_cia_without_its_tool_reports_failure(missing, recording_command):
    assert threeds.extract_3ds_cia("/in/Game.cia", "/out") is False
    assert recording_command.ran() is False


def test_a_failed_cia_extract_reports_failure(installed, monkeypatch, scratch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert threeds.extract_3ds_cia("/in/Game.cia", "/out") is False


def test_an_empty_extraction_reports_failure(installed, recording_command, scratch, existing_output, monkeypatch):
    # A run that produced an empty directory is not an extraction.
    monkeypatch.setattr(threeds.paths, "get_directory_contents", lambda path: [])
    monkeypatch.setattr(threeds.paths, "is_directory_empty", lambda path: True)
    monkeypatch.setattr(filebulk, "move_contents", lambda **kwargs: True)

    assert threeds.extract_3ds_cia("/in/Game.cia", "/out") is False


###########################################################
# 3DS information and installation
###########################################################

def test_file_info_is_returned_as_the_tool_printed_it(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id:          0004000000123400")

    assert threeds.get_3ds_file_info("/in/Game.cia") == "Title id:          0004000000123400"


def test_file_info_without_its_tool_is_empty(missing, recording_command):
    assert threeds.get_3ds_file_info("/in/Game.cia") == ""
    assert recording_command.ran() is False


def test_installing_a_cia_uses_the_title_id_for_its_path(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id:          0004000000123400")
    seen = {}

    def extract_3ds_cia(src_3ds_file, extract_dir, **kwargs):
        seen["dir"] = extract_dir
        return True

    monkeypatch.setattr(threeds, "extract_3ds_cia", extract_3ds_cia)

    assert threeds.install_3ds_cia("/in/Game.cia", "/sdmc") is True
    assert seen["dir"].endswith(os.path.join("title", "00040000", "00123400", "content"))


def test_installing_a_cia_lowercases_the_title_id(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id:          000400000012AB00")
    seen = {}

    def extract_3ds_cia(src_3ds_file, extract_dir, **kwargs):
        seen["dir"] = extract_dir
        return True

    monkeypatch.setattr(threeds, "extract_3ds_cia", extract_3ds_cia)
    threeds.install_3ds_cia("/in/Game.cia", "/sdmc")

    assert seen["dir"].endswith(os.path.join("00040000", "0012ab00", "content"))


@pytest.mark.parametrize("output", [
    "",
    "Title id:          00040000",
    "no fields at all",
])
def test_a_cia_without_a_usable_title_id_is_not_installed(installed, monkeypatch, output):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = output)

    def fail(*args, **kwargs):
        raise AssertionError("nothing may be extracted without a title id")

    monkeypatch.setattr(threeds, "extract_3ds_cia", fail)

    assert threeds.install_3ds_cia("/in/Game.cia", "/sdmc") is False


def test_a_cia_that_will_not_extract_is_not_installed(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id:          0004000000123400")
    monkeypatch.setattr(threeds, "extract_3ds_cia", lambda **kwargs: False)

    assert threeds.install_3ds_cia("/in/Game.cia", "/sdmc") is False


def test_extracting_a_cia_without_a_scratch_directory_reports_failure(installed, recording_command, no_scratch):
    assert threeds.extract_3ds_cia("/in/Game.cia", "/out") is False
    assert recording_command.ran() is False


def test_a_title_id_line_with_extra_fields_is_skipped(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "Title id: 0004:0000\nTitle id:          0004000000123400")
    seen = {}
    monkeypatch.setattr(
        threeds, "extract_3ds_cia",
        lambda src_3ds_file, extract_dir, **kwargs: seen.setdefault("dir", extract_dir) and True)

    assert threeds.install_3ds_cia("/in/Game.cia", "/sdmc") is True
    assert seen["dir"].endswith(os.path.join("00040000", "00123400", "content"))
