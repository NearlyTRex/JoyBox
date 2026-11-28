# Imports
import types

# Third-party imports
import pytest

# Local imports
from joybox import logger
from joybox.audiometadata import audiofile


class OpenError(Exception):
    pass


@pytest.fixture
def logged(monkeypatch):
    seen = {"errors": [], "infos": []}
    monkeypatch.setattr(logger, "log_error", lambda message, quit_program = False: seen["errors"].append(message))
    monkeypatch.setattr(logger, "log_info", seen["infos"].append)
    return seen


def load(path, open_func, verbose = False):
    return audiofile.load_audio_file(path, open_func, OpenError, "Failed to open", "Opening %s" % path, verbose = verbose)


def test_a_missing_file_is_not_opened(tmp_path, logged):
    path = str(tmp_path / "absent.mp3")

    assert load(path, lambda f: pytest.fail("opened")) is None
    assert logged["errors"] == ["Audio file not found: %s" % path]


def test_an_existing_file_comes_back_opened(tmp_path, logged):
    target = tmp_path / "track.mp3"
    target.write_bytes(b"audio")

    assert load(str(target), lambda f: ("opened", f), verbose = True) == ("opened", str(target))
    assert logged["infos"] == ["Opening %s" % target]


def test_a_quiet_load_logs_nothing(tmp_path, logged):
    target = tmp_path / "track.mp3"
    target.write_bytes(b"audio")

    assert load(str(target), lambda f: "opened") == "opened"
    assert logged["infos"] == []


def test_an_unreadable_file_logs_why(tmp_path, logged):
    target = tmp_path / "track.mp3"
    target.write_bytes(b"audio")

    def refuse(f):
        raise OpenError("bad header")

    assert load(str(target), refuse) is None
    assert logged["errors"] == ["Failed to open: bad header"]


def test_the_file_info_reads_the_stream_and_tag_presence(tmp_path):
    target = tmp_path / "track.mp3"
    target.write_bytes(b"12345")
    audio = types.SimpleNamespace(info = types.SimpleNamespace(bitrate = 128000, length = 3.5), tags = None)

    assert audiofile.build_audio_file_info(str(target), audio) == {
        "path": str(target),
        "size": 5,
        "bitrate": 128000,
        "length": 3.5,
        "sample_rate": 0,
        "channels": 0,
        "has_tags": False,
    }
