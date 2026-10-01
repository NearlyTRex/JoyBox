# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.stores import amazon
from amazon_helpers import APPID, NILE, PYTHON


@pytest.fixture
def temp(amazon_store, tools, recording_command, monkeypatch, tmp_path):
    state = {"archived": [], "archive_ok": True, "temp": tmp_path / "nile-temp"}

    def create_temporary_directory(**kwargs):
        state["temp"].mkdir()
        return (True, str(state["temp"]))
    monkeypatch.setattr(amazon.fileops, "create_temporary_directory", create_temporary_directory)

    def archive_folder(input_path, output_path, **kwargs):
        state["archived"].append((input_path, output_path, kwargs))
        if state["archive_ok"]:
            os.makedirs(output_path, exist_ok = True)
            open(os.path.join(output_path, "game.7z"), "w").close()
        return state["archive_ok"]
    monkeypatch.setattr(amazon.backup, "archive_folder", archive_folder)
    return state


###########################################################
# Downloading
###########################################################

def test_a_download_is_archived_and_its_temp_removed(amazon_store, temp, recording_command, tmp_path):
    output = str(tmp_path / "out")

    assert amazon_store.download(APPID, output, output_name = "Game", skip_existing = True) is True

    assert recording_command.only() == [PYTHON, NILE, "verify", "--path", str(temp["temp"]), APPID]
    input_path, output_path, kwargs = temp["archived"][0]
    assert (input_path, output_path) == (str(temp["temp"]), output)
    assert kwargs["output_name"] == "Game" and kwargs["skip_existing"] is True
    assert not temp["temp"].exists()


def test_a_download_that_archives_nothing_fails(amazon_store, temp, monkeypatch, tmp_path):
    monkeypatch.setattr(amazon.backup, "archive_folder", lambda **kwargs: True)

    assert amazon_store.download(APPID, str(tmp_path / "out")) is False
    assert not temp["temp"].exists()


def test_a_failed_download_removes_its_temp(amazon_store, temp, recording_command, tmp_path):
    recording_command.returncode = 1

    assert amazon_store.download(APPID, str(tmp_path / "out")) is False
    assert temp["archived"] == []
    assert not temp["temp"].exists()


def test_a_failed_archive_removes_its_temp(amazon_store, temp, tmp_path):
    temp["archive_ok"] = False

    assert amazon_store.download(APPID, str(tmp_path / "out")) is False
    assert not temp["temp"].exists()


def test_a_download_needs_a_temp_directory(amazon_store, temp, recording_command, monkeypatch, tmp_path):
    monkeypatch.setattr(amazon.fileops, "create_temporary_directory", lambda **kwargs: (False, "no"))

    assert amazon_store.download(APPID, str(tmp_path / "out")) is False
    assert recording_command.calls == []


def test_an_invalid_identifier_downloads_nothing(amazon_store, temp, recording_command, tmp_path):
    assert amazon_store.download("", str(tmp_path / "out")) is False
    assert recording_command.calls == []


@pytest.mark.parametrize("tool", ["PythonVenvPython", "Nile"])
def test_a_download_needs_python_and_nile(amazon_store, temp, tools, recording_command, tmp_path, tool):
    del tools[tool]

    assert amazon_store.download(APPID, str(tmp_path / "out")) is False
    assert recording_command.calls == []
    assert not temp["temp"].exists()
