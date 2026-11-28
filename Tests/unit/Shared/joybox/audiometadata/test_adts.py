# Imports
import importlib

# Third-party imports
import pytest

# Local imports
from joybox import audiometadata
from joybox import logger
from joybox import modules
from joybox import serialization
from audiometadata_helpers import artwork, build_adts, build_m4a


###########################################################
# Telling the two kinds of .aac apart
#
# An .aac is either an MP4 container or a raw ADTS stream; the wrong reader
# fails to parse it, so the choice is made from the bytes, not the name.
###########################################################

def test_an_aac_with_an_ftyp_box_goes_to_mp4(metadata, tmp_path):
    target = tmp_path / "track.aac"
    target.write_bytes(build_m4a())

    assert metadata.is_mp4_audio_file(str(target)) is True
    assert metadata.is_adts_audio_file(str(target)) is False
    assert metadata.set_tags(str(target), {"title": "A Title"}) is True
    assert metadata.get_mp4_tags(str(target))["title"] == "A Title"
    assert "codec" in metadata.get_file_info(str(target))


def test_an_aac_without_an_ftyp_box_is_adts(metadata, adts_file):
    assert metadata.is_mp4_audio_file(adts_file) is False
    assert metadata.is_adts_audio_file(adts_file) is True


@pytest.mark.parametrize("name, expected", [
    ("track.m4a", True), ("track.M4B", True), ("track.mp4", True), ("track.mp3", False)])
def test_other_extensions_are_chosen_by_name(metadata, tmp_path, name, expected):
    target = tmp_path / name
    target.write_bytes(b"")

    assert metadata.is_mp4_audio_file(str(target)) is expected
    assert metadata.is_adts_audio_file(str(target)) is False


def test_a_file_too_short_or_unreadable_has_no_container(metadata, tmp_path, monkeypatch):
    short = tmp_path / "short.aac"
    short.write_bytes(b"\0\0")
    assert metadata.has_mp4_container(str(short)) is False

    monkeypatch.setattr(serialization, "read_binary_file", lambda *args, **kwargs: None)
    assert metadata.has_mp4_container(str(short)) is False


###########################################################
# ADTS tags
#
# A raw stream has no tag atoms; its tag is a standalone ID3v2 header, created
# on the first write and read with the same frame mapping as an MP3.
###########################################################

def test_an_untagged_stream_reads_as_empty(metadata, adts_file):
    assert metadata.get_tags(adts_file) == {}
    assert metadata.has_tags(adts_file) is False


def test_the_first_write_creates_an_id3_header(metadata, adts_file):
    assert metadata.set_tags(adts_file, {"title": "A Title", "artist": "An Artist"}) is True

    assert serialization.read_binary_file(adts_file, length = 3) == b"ID3"
    assert metadata.has_tags(adts_file) is True
    tags = metadata.get_tags(adts_file)
    assert (tags["title"], tags["artist"]) == ("A Title", "An Artist")


def test_the_stream_still_parses_after_tagging(metadata, adts_file):
    metadata.set_tags(adts_file, {"title": "A Title"})
    info = metadata.get_file_info(adts_file)

    assert info["sample_rate"] == 44100
    assert info["channels"] == 2
    assert info["has_tags"] is True


def test_a_second_write_updates_the_existing_header(metadata, adts_file):
    metadata.set_tags(adts_file, {"artist": "An Artist"})
    metadata.set_tags(adts_file, {"title": "A Title"})

    tags = metadata.get_tags(adts_file)
    assert (tags["title"], tags["artist"]) == ("A Title", "An Artist")


def test_a_pretend_write_leaves_the_stream_untouched(metadata, adts_file):
    assert metadata.set_tags(adts_file, {"title": "A Title"}, pretend_run = True) is True

    assert serialization.read_binary_file(adts_file) == build_adts()


def test_removal_strips_the_header(metadata, adts_file):
    metadata.set_tags(adts_file, {"title": "A Title"})

    assert metadata.remove_tags(adts_file) is True
    assert serialization.read_binary_file(adts_file) == build_adts()
    assert metadata.get_file_info(adts_file)["has_tags"] is False


def test_removal_can_keep_the_artwork(metadata, adts_file):
    metadata.set_tags(adts_file, {"title": "A Title", "artwork": [artwork()]})

    assert metadata.remove_tags(adts_file, preserve_artwork = True) is True
    tags = metadata.get_tags(adts_file, include_artwork = True)
    assert "title" not in tags
    assert [art["desc"] for art in tags["artwork"]] == ["cover"]


def test_an_aac_that_is_neither_container_is_reported_and_left_alone(metadata, tmp_path):
    other = tmp_path / "noise.aac"
    other.write_bytes(b"not audio at all" * 8)

    assert metadata.get_tags(str(other)) is None
    assert metadata.has_tags(str(other)) is False
    assert metadata.set_tags(str(other), {"title": "A Title"}) is False
    assert metadata.remove_tags(str(other)) is False
    assert metadata.get_file_info(str(other)) is None
    assert other.read_bytes() == b"not audio at all" * 8


###########################################################
# ADTS stream info
###########################################################

def test_stream_info_is_read_from_the_frames(metadata, adts_file):
    info = metadata.get_adts_file_info(adts_file, verbose = True)

    assert info["path"] == adts_file
    assert info["size"] == len(build_adts())
    assert info["bitrate"] > 0
    assert info["length"] > 0
    assert info["has_tags"] is False


def test_stream_info_for_a_missing_file_is_reported(metadata, tmp_path, monkeypatch):
    errors = []
    monkeypatch.setattr(logger, "log_error", lambda message, quit_program = False: errors.append(message))

    assert metadata.get_adts_file_info(str(tmp_path / "absent.aac")) is None
    assert errors


###########################################################
# Loading mutagen.aac
#
# It is loaded through the Mutagen tool like the other modules, but only when
# a raw stream turns up, so MP3 and MP4 work does not depend on it.
###########################################################

def test_mutagen_aac_is_loaded_once_by_its_tool_name(metadata, adts_file, monkeypatch):
    requested = []

    def import_package(module_path, module_name):
        requested.append(module_name)
        return importlib.import_module(module_name)
    monkeypatch.setattr(modules, "import_python_module_package", import_package)

    metadata.get_file_info(adts_file)
    metadata.get_tags(adts_file)

    assert requested == ["mutagen.aac"]


def test_a_missing_mutagen_aac_is_an_import_error(monkeypatch, adts_file):
    monkeypatch.setattr(modules, "import_python_module_package",
        lambda module_path, module_name: None if module_name == "mutagen.aac" else importlib.import_module(module_name))
    metadata = audiometadata.AudioMetadata()

    with pytest.raises(ImportError):
        metadata.get_tags(adts_file)
