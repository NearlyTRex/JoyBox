# Imports
import pytest

# Local imports
from joybox import playstation


###########################################################
# PSV stripping and trimming
###########################################################

def test_stripping_uses_the_strip_mode(installed, recording_command, existing_output):
    playstation.strip_psv("/in/Game.psv", "/out/Game.psv")

    assert recording_command.only() == \
        ["/tools/psvstrip", "-psvstrip", "/in/Game.psv", "/out/Game.psv"]


def test_unstripping_passes_the_side_file_last(installed, recording_command, existing_output):
    # -applypsve takes source, destination and then the .psve it reapplies.
    playstation.unstrip_psv("/in/Game.psv", "/in/Game.psve", "/out/Game.psv")

    assert recording_command.only() == \
        ["/tools/psvstrip", "-applypsve", "/in/Game.psv", "/out/Game.psv", "/in/Game.psve"]


def test_trimming_uses_the_trim_flag(installed, recording_command, existing_output):
    playstation.trim_psv("/in/Game.psv", "/out/Game.psv")

    assert "--trim" in recording_command.only()
    assert "--expand" not in recording_command.only()


def test_untrimming_uses_the_expand_flag(installed, recording_command, existing_output):
    playstation.untrim_psv("/in/Game.psv", "/out/Game.psv")

    assert "--expand" in recording_command.only()
    assert "--trim" not in recording_command.only()


@pytest.mark.parametrize("wrapper", [playstation.trim_psv, playstation.untrim_psv])
def test_the_output_file_is_named_with_o(installed, recording_command, existing_output, wrapper):
    wrapper("/in/Game.psv", "/out/Game.psv")

    assert recording_command.value_after("-o") == "/out/Game.psv"
    assert recording_command.only()[-1] == "/in/Game.psv"


def test_verifying_passes_only_the_image(installed, recording_command, existing_output):
    playstation.verify_psv("/in/Game.psv")

    assert recording_command.only() == \
        ["/tools/venv/python", "/tools/psvtools.py", "--verify", "/in/Game.psv"]


def test_a_verified_image_needs_no_output_file(installed, recording_command):
    # Verification writes nothing, so it must not be judged by a result file.
    assert playstation.verify_psv("/in/Game.psv") is True


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.unstrip_psv, ("/in/Game.psv", "/in/Game.psve", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.verify_psv, ("/in/Game.psv",)),
])
def test_a_psv_wrapper_without_its_tool_reports_failure(missing, recording_command, wrapper, args):
    assert wrapper(*args) is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.unstrip_psv, ("/in/Game.psv", "/in/Game.psve", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.verify_psv, ("/in/Game.psv",)),
])
def test_a_failed_psv_wrapper_reports_failure(installed, monkeypatch, wrapper, args):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert wrapper(*args) is False


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.unstrip_psv, ("/in/Game.psv", "/in/Game.psve", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.verify_psv, ("/in/Game.psv",)),
])
def test_a_failed_psv_wrapper_can_quit_the_program(installed, monkeypatch, wrapper, args):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    with pytest.raises(SystemExit):
        wrapper(*args, exit_on_failure = True)


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
])
def test_a_psv_wrapper_can_remove_the_source(installed, recording_command, existing_output, monkeypatch, wrapper, args):
    removed = []
    monkeypatch.setattr(playstation.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    wrapper(*args, delete_original = True)

    assert removed == ["/in/Game.psv"]


@pytest.mark.parametrize("wrapper,args", [
    (playstation.strip_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
])
def test_a_failed_psv_wrapper_keeps_the_source(installed, monkeypatch, wrapper, args):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    def fail(*args, **kwargs):
        raise AssertionError("the source must survive a failed conversion")

    monkeypatch.setattr(playstation.fileops, "remove_file", fail)

    assert wrapper(*args, delete_original = True) is False


@pytest.mark.parametrize("wrapper,args", [
    (playstation.trim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.untrim_psv, ("/in/Game.psv", "/out/Game.psv")),
    (playstation.verify_psv, ("/in/Game.psv",)),
])
def test_a_psv_wrapper_without_its_script_reports_failure(venv_only, recording_command, wrapper, args):
    assert wrapper(*args) is False
    assert recording_command.ran() is False


def test_unstripping_can_remove_the_stripped_source(installed, recording_command, existing_output, monkeypatch):
    removed = []
    monkeypatch.setattr(playstation.fileops, "remove_file", lambda src, **kwargs: removed.append(src))

    playstation.unstrip_psv("/in/Game.psv", "/in/Game.psve", "/out/Game.psv", delete_original = True)

    assert removed == ["/in/Game.psv"]


###########################################################
# PSV app content
###########################################################

def make_app(root, *parts, title_id = "PCSE00001"):
    from fakes import write_param_sfo
    app = root.joinpath(*parts)
    write_param_sfo(app / "sce_sys" / "param.sfo", {"TITLE_ID": title_id, "ATTRIBUTE": 0x8000})
    return app


def test_reading_param_sfo_returns_strings_and_integers(tmp_path):
    sfo_file = make_app(tmp_path, "app") / "sce_sys" / "param.sfo"

    assert playstation.read_param_sfo(str(sfo_file)) == {"TITLE_ID": "PCSE00001", "ATTRIBUTE": 0x8000}


def test_reading_a_file_without_the_psf_magic_gives_nothing(tmp_path):
    sfo_file = tmp_path / "param.sfo"
    sfo_file.write_bytes(b"\x00XYZ" + bytes(16))

    assert playstation.read_param_sfo(str(sfo_file)) is None


def test_reading_a_missing_param_sfo_gives_nothing(tmp_path):
    assert playstation.read_param_sfo(str(tmp_path / "param.sfo")) is None


def test_the_content_root_is_the_app_with_the_matching_title(tmp_path):
    make_app(tmp_path, "EP0001-PCSE00002_00-X", title_id = "PCSE00002")
    wanted = make_app(tmp_path, "EP0001-PCSE00001_00-X")

    assert playstation.find_psv_content_root(str(tmp_path), "PCSE00001") == str(wanted)


def test_a_single_app_is_the_content_root_whatever_its_title(tmp_path):
    only = make_app(tmp_path, "content", title_id = "PCSE09999")
    make_app(only, "sce_module", title_id = "PCSE08888")

    assert playstation.find_psv_content_root(str(tmp_path), "PCSE00001") == str(only)


def test_an_unreadable_param_sfo_still_marks_a_content_root(tmp_path):
    app = tmp_path / "app"
    (app / "sce_sys").mkdir(parents = True)
    (app / "sce_sys" / "param.sfo").write_bytes(b"")

    assert playstation.find_psv_content_root(str(tmp_path), "PCSE00001") == str(app)


def test_several_unmatched_apps_have_no_content_root(tmp_path):
    make_app(tmp_path, "a", title_id = "PCSE00002")
    make_app(tmp_path, "b", title_id = "PCSE00003")

    assert playstation.find_psv_content_root(str(tmp_path), "PCSE00001") is None


def test_a_cartridge_dump_has_no_content_root(tmp_path):
    (tmp_path / "Game.psv").write_bytes(b"")

    assert playstation.find_psv_content_root(str(tmp_path), "PCSE00001") is None
