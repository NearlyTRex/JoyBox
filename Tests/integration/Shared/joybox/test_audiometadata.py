# Imports
import base64
import importlib
import os
import shutil
import subprocess

# Third-party imports
import pytest

# Local imports
from joybox import audiometadata

pytestmark = pytest.mark.slow


###########################################################
# Audio tags against real mutagen
#
# The tags are the only record of what a downloaded track is; the filename is
# derived and the source is gone. A write that reports success without
# landing, or a read that returns a frame object instead of its text, is a
# library that collects unlabelled files.
###########################################################

# A silent MPEG-1 Layer III frame, repeated enough for mutagen to parse it as
# audio. Built here rather than fetched so the tests need no external tool.
MP3_FRAME = b"\xff\xfb\x90\x00" + b"\x00" * 413

# A one pixel PNG, for the artwork frames
PNG_PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


@pytest.fixture(scope = "module")
def metadata():
    # The tag classes come from a vendored mutagen that a hermetic run has no
    # copy of. The import is the seam; the tagging is what is under test.
    loaded = [
        importlib.import_module(name)
        for name in ("mutagen", "mutagen.mp3", "mutagen.id3", "mutagen.mp4")
    ]
    pending = iter(loaded)
    original = audiometadata.modules.import_python_module_package
    audiometadata.modules.import_python_module_package = \
        lambda module_path, module_name: next(pending)
    try:
        yield audiometadata.AudioMetadata()
    finally:
        audiometadata.modules.import_python_module_package = original


@pytest.fixture
def mp3_file(tmp_path):
    target = tmp_path / "track.mp3"
    target.write_bytes(MP3_FRAME * 40)
    return str(target)


@pytest.fixture
def m4a_file(tmp_path):
    if not shutil.which("ffmpeg"):
        pytest.skip("ffmpeg is not installed")
    target = str(tmp_path / "track.m4a")
    result = subprocess.run([
        "ffmpeg", "-loglevel", "error", "-y",
        "-f", "lavfi", "-i", "anullsrc=r=44100:cl=mono",
        "-t", "0.2", "-c:a", "aac", target,
    ], capture_output = True)
    assert result.returncode == 0, result.stderr.decode()
    return target


###########################################################
# ID3 tags
###########################################################

def test_a_tag_is_written_and_read_back(metadata, mp3_file):
    assert metadata.set_id3_tags(mp3_file, {"title": "A Title"}) is True
    assert metadata.get_id3_tags(mp3_file)["title"] == "A Title"


def value_for(field):
    # The year frame holds a timestamp rather than free text, so it needs a
    # value the frame will actually keep.
    if field == "year":
        return "1998"
    return "value-for-%s" % field


@pytest.mark.parametrize("field", audiometadata.curated_tag_fields)
def test_every_curated_field_survives_a_round_trip(metadata, mp3_file, field):
    # Each field is a different ID3 frame, and one mapped to the wrong frame
    # reads back as another field's value or not at all.
    metadata.set_id3_tags(mp3_file, {field: value_for(field)})

    assert metadata.get_id3_tags(mp3_file)[field] == value_for(field)


@pytest.mark.parametrize("field", audiometadata.curated_tag_fields)
def test_no_two_curated_fields_share_a_frame(metadata, mp3_file, field):
    metadata.set_id3_tags(mp3_file, {field: value_for(field)})
    tags = metadata.get_id3_tags(mp3_file)

    for other in audiometadata.curated_tag_fields:
        if other == field:
            continue
        assert tags.get(other) != value_for(field), \
            "%s and %s share a frame" % (field, other)


def test_several_tags_are_written_at_once(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {
        "title": "A Title",
        "artist": "An Artist",
        "album": "An Album",
    })

    tags = metadata.get_id3_tags(mp3_file)

    assert tags["title"] == "A Title"
    assert tags["artist"] == "An Artist"
    assert tags["album"] == "An Album"


def test_a_tag_is_replaced_rather_than_repeated(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"title": "First"})
    metadata.set_id3_tags(mp3_file, {"title": "Second"})

    assert metadata.get_id3_tags(mp3_file)["title"] == "Second"


def test_writing_one_tag_leaves_the_others(metadata, mp3_file):
    # Tagging happens in passes, and a write that cleared everything else
    # would lose whatever the previous pass established.
    metadata.set_id3_tags(mp3_file, {"artist": "An Artist"})
    metadata.set_id3_tags(mp3_file, {"title": "A Title"})

    assert metadata.get_id3_tags(mp3_file)["artist"] == "An Artist"


def test_existing_tags_can_be_cleared_first(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"artist": "An Artist"})
    metadata.set_id3_tags(mp3_file, {"title": "A Title"}, clear_existing = True)

    tags = metadata.get_id3_tags(mp3_file)

    assert tags["title"] == "A Title"
    assert not tags.get("artist")


def test_a_numeric_tag_is_stored_as_text(metadata, mp3_file):
    # Track numbers arrive as integers and ID3 frames hold text.
    metadata.set_id3_tags(mp3_file, {"track_number": 7})

    assert metadata.get_id3_tags(mp3_file)["track_number"] == "7"


def test_an_untagged_file_has_no_tags(metadata, mp3_file):
    assert metadata.has_id3_tags(mp3_file) is False


def test_a_tagged_file_reports_its_tags(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"title": "A Title"})

    assert metadata.has_id3_tags(mp3_file) is True


def test_tags_can_be_removed(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"title": "A Title"})

    assert metadata.remove_id3_tags(mp3_file) is True
    assert not metadata.get_id3_tags(mp3_file).get("title")


def test_a_comment_survives_a_round_trip(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {
        "comments": [{"desc": "note", "lang": "eng", "text": "A comment"}],
    })

    tags = metadata.get_id3_tags(mp3_file)

    assert any(comment["text"] == "A comment" for comment in tags["comments"])


def test_comments_can_be_left_out_of_a_read(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {
        "comments": [{"desc": "note", "lang": "eng", "text": "A comment"}],
    })

    tags = metadata.get_id3_tags(mp3_file, exclude_comments = True)

    assert not tags.get("comments")


def test_artwork_survives_a_round_trip(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {
        "artwork": [{
            "data": base64.b64encode(PNG_PIXEL).decode("ascii"),
            "mime": "image/png",
            "type": 3,
            "desc": "cover",
        }],
    })

    tags = metadata.get_id3_tags(mp3_file)

    assert tags["artwork"]
    assert base64.b64decode(tags["artwork"][0]["data"])


def test_artwork_can_be_left_out_of_a_read(metadata, mp3_file):
    # Artwork is megabytes; a listing that does not show it should not carry
    # it either.
    metadata.set_id3_tags(mp3_file, {
        "artwork": [{
            "data": base64.b64encode(PNG_PIXEL).decode("ascii"),
            "mime": "image/png",
            "type": 3,
            "desc": "cover",
        }],
    })

    tags = metadata.get_id3_tags(mp3_file, include_artwork = False)

    assert not tags.get("artwork")


def test_artwork_can_be_kept_while_other_tags_are_removed(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {
        "title": "A Title",
        "artwork": [{
            "data": base64.b64encode(PNG_PIXEL).decode("ascii"),
            "mime": "image/png",
            "type": 3,
            "desc": "cover",
        }],
    })

    metadata.remove_id3_tags(mp3_file, preserve_artwork = True)
    tags = metadata.get_id3_tags(mp3_file)

    assert tags["artwork"]
    assert not tags.get("title")


def test_a_missing_file_has_no_tags(metadata, tmp_path):
    assert metadata.get_id3_tags(str(tmp_path / "absent.mp3")) is None


def test_a_missing_file_cannot_be_tagged(metadata, tmp_path):
    assert metadata.set_id3_tags(str(tmp_path / "absent.mp3"), {"title": "A Title"}) is False


###########################################################
# MP4 tags
###########################################################

def test_an_mp4_tag_is_written_and_read_back(metadata, m4a_file):
    assert metadata.set_mp4_tags(m4a_file, {"title": "A Title"}) is True
    assert metadata.get_mp4_tags(m4a_file)["title"] == "A Title"


@pytest.mark.parametrize("field", ["title", "artist", "album", "genre", "album_artist"])
def test_every_common_mp4_field_survives_a_round_trip(metadata, m4a_file, field):
    metadata.set_mp4_tags(m4a_file, {field: "value-for-%s" % field})

    assert metadata.get_mp4_tags(m4a_file)[field] == "value-for-%s" % field


def test_no_two_mp4_fields_share_an_atom(metadata, m4a_file):
    fields = ["title", "artist", "album", "genre", "album_artist"]
    metadata.set_mp4_tags(m4a_file, {field: "value-for-%s" % field for field in fields})

    tags = metadata.get_mp4_tags(m4a_file)

    assert len({tags[field] for field in fields}) == len(fields)


def test_an_mp4_with_its_tags_removed_has_none(metadata, m4a_file):
    # The encoder stamps its own tag, so "untagged" means after a removal.
    metadata.remove_mp4_tags(m4a_file)

    assert metadata.has_mp4_tags(m4a_file) is False


def test_a_tagged_mp4_reports_its_tags(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"title": "A Title"})

    assert metadata.has_mp4_tags(m4a_file) is True


def test_mp4_tags_can_be_removed(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"title": "A Title"})

    assert metadata.remove_mp4_tags(m4a_file) is True
    assert not metadata.get_mp4_tags(m4a_file).get("title")


def test_an_mp4_reports_its_file_info(metadata, m4a_file):
    info = metadata.get_mp4_file_info(m4a_file)

    assert info is not None
    assert info.get("length") or info.get("duration") or info


###########################################################
# Choosing the format from the file
###########################################################

def test_an_mp3_is_tagged_as_an_mp3(metadata, mp3_file):
    # The dispatcher picks the tag format from the extension; the wrong one
    # fails to parse the container entirely.
    assert metadata.set_tags(mp3_file, {"title": "A Title"}) is True
    assert metadata.get_tags(mp3_file)["title"] == "A Title"


def test_an_mp4_is_tagged_as_an_mp4(metadata, m4a_file):
    assert metadata.set_tags(m4a_file, {"title": "A Title"}) is True
    assert metadata.get_tags(m4a_file)["title"] == "A Title"


def test_a_tagged_file_is_reported_as_tagged(metadata, mp3_file):
    metadata.set_tags(mp3_file, {"title": "A Title"})

    assert metadata.has_tags(mp3_file) is True


def test_tags_are_removed_whatever_the_format(metadata, mp3_file):
    metadata.set_tags(mp3_file, {"title": "A Title"})

    assert metadata.remove_tags(mp3_file) is True
    assert not metadata.get_tags(mp3_file).get("title")


def test_file_info_is_read_whatever_the_format(metadata, mp3_file):
    assert metadata.get_file_info(mp3_file) is not None


def test_a_file_that_is_not_audio_is_reported_rather_than_raising(metadata, tmp_path):
    # A sweep over a mixed directory hands these in, and the mp4 path already
    # reported them instead of raising.
    other = tmp_path / "notes.txt"
    other.write_text("not audio")

    assert metadata.get_tags(str(other)) is None
    assert metadata.has_tags(str(other)) is False
    assert metadata.set_tags(str(other), {"title": "A Title"}) is False
    assert metadata.remove_tags(str(other)) is False
