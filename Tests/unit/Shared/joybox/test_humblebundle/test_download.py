# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.stores import humblebundle
from humble_helpers import MANAGER_CMD

APPNAME = "tombraider_windows"


@pytest.fixture
def temp(humble_store, tools, recording_command, monkeypatch, tmp_path):
    state = {"archived": [], "archive_ok": True, "temp": tmp_path / "humble-temp"}

    def create_temporary_directory(**kwargs):
        state["temp"].mkdir()
        return (True, str(state["temp"]))
    monkeypatch.setattr(humblebundle.fileops, "create_temporary_directory", create_temporary_directory)

    def archive_folder(input_path, output_path, **kwargs):
        state["archived"].append((input_path, output_path, kwargs))
        if state["archive_ok"]:
            os.makedirs(output_path, exist_ok = True)
            open(os.path.join(output_path, "game.7z"), "w").close()
        return state["archive_ok"]
    monkeypatch.setattr(humblebundle.backup, "archive_folder", archive_folder)
    return state


###########################################################
# Downloading
###########################################################

def test_a_download_is_archived_and_its_temp_removed(humble_store, temp, recording_command, tmp_path):
    output = str(tmp_path / "out")

    assert humble_store.download(APPNAME, output, output_name = "Game", skip_existing = True) is True

    assert recording_command.only() == MANAGER_CMD + [
        "--download", APPNAME, "--platform", "windows", "--path", str(temp["temp"]), "--quiet"]
    input_path, output_path, kwargs = temp["archived"][0]
    assert (input_path, output_path) == (str(temp["temp"]), output)
    assert kwargs["output_name"] == "Game" and kwargs["skip_existing"] is True
    assert not temp["temp"].exists()


def test_a_download_passes_its_flags_through(humble_store, temp, recording_command, tmp_path):
    humble_store.download(APPNAME, str(tmp_path / "out"), verbose = True, pretend_run = True, exit_on_failure = True)

    assert recording_command.calls[0]["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}
    assert temp["archived"][0][2]["pretend_run"] is True


def test_a_download_that_archives_nothing_fails(humble_store, temp, monkeypatch, tmp_path):
    monkeypatch.setattr(humblebundle.backup, "archive_folder", lambda **kwargs: True)

    assert humble_store.download(APPNAME, str(tmp_path / "out")) is False
    assert not temp["temp"].exists()


def test_a_failed_download_removes_its_temp(humble_store, temp, recording_command, tmp_path):
    recording_command.returncode = 1

    assert humble_store.download(APPNAME, str(tmp_path / "out")) is False
    assert temp["archived"] == []
    assert not temp["temp"].exists()


def test_a_failed_archive_removes_its_temp(humble_store, temp, tmp_path):
    temp["archive_ok"] = False

    assert humble_store.download(APPNAME, str(tmp_path / "out")) is False
    assert not temp["temp"].exists()


def test_a_crashing_archive_removes_its_temp(humble_store, temp, monkeypatch, tmp_path):
    def archive_folder(**kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(humblebundle.backup, "archive_folder", archive_folder)

    with pytest.raises(OSError):
        humble_store.download(APPNAME, str(tmp_path / "out"))
    assert not temp["temp"].exists()


def test_a_download_needs_a_temp_directory(humble_store, temp, recording_command, monkeypatch, tmp_path):
    monkeypatch.setattr(humblebundle.fileops, "create_temporary_directory", lambda **kwargs: (False, "no"))

    assert humble_store.download(APPNAME, str(tmp_path / "out")) is False
    assert recording_command.calls == []


@pytest.mark.parametrize("identifier", ["", None])
def test_an_invalid_identifier_downloads_nothing(humble_store, temp, recording_command, tmp_path, identifier):
    assert humble_store.download(identifier, str(tmp_path / "out")) is False
    assert recording_command.calls == []
    assert not temp["temp"].exists()


@pytest.mark.parametrize("tool", ["PythonVenvPython", "HumbleBundleManager"])
def test_a_download_needs_python_and_the_manager(humble_store, temp, tools, recording_command, tmp_path, tool):
    del tools[tool]

    assert humble_store.download(APPNAME, str(tmp_path / "out")) is False
    assert recording_command.calls == []
    assert not temp["temp"].exists()
