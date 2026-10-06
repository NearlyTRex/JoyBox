# Imports
import base64

# Third-party imports
import pytest

# Local imports
from joybox import audiometadata
from joybox import config
from audiometadata_helpers import PNG_PIXEL, artwork


###########################################################
# ID3 tags
#
# The tags are the only record of what a downloaded track is; the filename is
# derived and the source is gone. A write that reports success without
# landing, or a read that returns a frame object instead of its text, is a
# library that collects unlabelled files.
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
    metadata.set_id3_tags(mp3_file, {"title": "A Title", "artist": "An Artist", "album": "An Album"})

    tags = metadata.get_id3_tags(mp3_file)

    assert (tags["title"], tags["artist"], tags["album"]) == ("A Title", "An Artist", "An Album")


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


def test_an_untagged_file_reads_as_empty(metadata, mp3_file):
    assert metadata.has_id3_tags(mp3_file) is False
    assert metadata.get_id3_tags(mp3_file) == {}


def test_a_tagged_file_reports_its_tags(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"title": "A Title"})

    assert metadata.has_id3_tags(mp3_file) is True


def test_tags_can_be_removed(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"title": "A Title"})

    assert metadata.remove_id3_tags(mp3_file) is True
    assert not metadata.get_id3_tags(mp3_file).get("title")
    assert metadata.remove_id3_tags(mp3_file) is True


###########################################################
# Pretend runs
#
# The apply and clear commands pass pretend_run straight through; a pretend
# run that rewrote the files would do exactly what it promised not to.
###########################################################

def test_a_pretend_write_leaves_the_file_alone(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"title": "Real"})

    assert metadata.set_id3_tags(mp3_file, {"title": "Pretend"}, pretend_run = True) is True
    assert metadata.get_id3_tags(mp3_file)["title"] == "Real"


def test_a_pretend_removal_leaves_the_file_alone(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"title": "Real"})

    assert metadata.remove_id3_tags(mp3_file, pretend_run = True) is True
    assert metadata.get_id3_tags(mp3_file)["title"] == "Real"


###########################################################
# Comments
###########################################################

def test_a_comment_survives_a_round_trip(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"comments": [{"desc": "note", "lang": "eng", "text": "A comment"}]})

    comments = metadata.get_id3_tags(mp3_file)["comments"]

    assert comments == [{"desc": "note", "lang": "eng", "text": "A comment"}]


def test_a_comment_defaults_its_language_and_description(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"comments": [{"text": "A comment"}]})

    assert metadata.get_id3_tags(mp3_file)["comments"] == [{"desc": "", "lang": "eng", "text": "A comment"}]


def test_comments_can_be_left_out_of_a_read(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"comments": [{"desc": "note", "lang": "eng", "text": "A comment"}]})

    assert not metadata.get_id3_tags(mp3_file, exclude_comments = True).get("comments")


###########################################################
# Artwork
###########################################################

def test_artwork_in_the_requested_format_is_read_as_is(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"artwork": [artwork()]})

    read = metadata.get_id3_tags(mp3_file, artwork_format = config.ImageFileType.PNG)["artwork"]

    assert read == [{"type": 3, "desc": "cover", "mime": "image/png", "data": artwork()["data"]}]


def test_artwork_is_converted_to_the_requested_format(metadata, mp3_file, monkeypatch):
    monkeypatch.setattr(audiometadata.image, "convert_image_data_to_format",
        lambda image_data, target_format: base64.b64encode(b"jpeg bytes").decode("ascii"))
    metadata.set_id3_tags(mp3_file, {"artwork": [artwork()]})

    read = metadata.get_id3_tags(mp3_file)["artwork"][0]

    assert read["mime"] == "image/jpeg"
    assert base64.b64decode(read["data"]) == b"jpeg bytes"


def test_artwork_that_cannot_be_converted_is_kept_as_it_was(metadata, mp3_file, monkeypatch):
    monkeypatch.setattr(audiometadata.image, "convert_image_data_to_format",
        lambda image_data, target_format: None)
    metadata.set_id3_tags(mp3_file, {"artwork": [artwork()]})

    read = metadata.get_id3_tags(mp3_file)["artwork"][0]

    assert read["mime"] == "image/png"
    assert base64.b64decode(read["data"]) == PNG_PIXEL


def test_artwork_can_be_left_out_of_a_read(metadata, mp3_file):
    # Artwork is megabytes; a listing that does not show it should not carry
    # it either.
    metadata.set_id3_tags(mp3_file, {"artwork": [artwork()]})

    assert not metadata.get_id3_tags(mp3_file, include_artwork = False).get("artwork")


def test_artwork_can_be_kept_while_other_tags_are_removed(metadata, mp3_file):
    metadata.set_id3_tags(mp3_file, {"title": "A Title", "artwork": [artwork()]})

    metadata.remove_id3_tags(mp3_file, preserve_artwork = True)
    tags = metadata.get_id3_tags(mp3_file, artwork_format = config.ImageFileType.PNG)

    assert tags["artwork"][0]["data"] == artwork()["data"]
    assert not tags.get("title")


###########################################################
# Missing and unreadable files
###########################################################

def test_a_missing_file(metadata, tmp_path):
    absent = str(tmp_path / "absent.mp3")
    assert metadata.get_id3_tags(absent) is None
    assert metadata.set_id3_tags(absent, {"title": "A Title"}) is False
    assert metadata.remove_id3_tags(absent) is False
    assert metadata.has_id3_tags(absent) is False
    assert metadata.get_audio_file_info(absent) is None


def test_a_file_that_is_not_an_mp3(metadata, tmp_path):
    other = tmp_path / "notes.mp3"
    other.write_text("not audio")
    assert metadata.get_id3_tags(str(other)) is None
    assert metadata.set_id3_tags(str(other), {"title": "A Title"}) is False
    assert metadata.remove_id3_tags(str(other)) is False
    assert metadata.has_id3_tags(str(other)) is False
    assert metadata.get_audio_file_info(str(other)) is None


def test_mp3_file_info(metadata, mp3_file):
    info = metadata.get_audio_file_info(mp3_file)

    assert info["path"] == mp3_file
    assert info["sample_rate"] == 44100
    assert info["length"] > 0
    assert info["has_tags"] is False


def test_the_class_needs_every_mutagen_module(monkeypatch):
    monkeypatch.setattr(audiometadata.modules, "import_python_module_package",
        lambda module_path, module_name: None)
    with pytest.raises(ImportError):
        audiometadata.AudioMetadata()


def test_kept_artwork_is_restored_when_removal_drops_the_tag_block(metadata, mp3_file, monkeypatch):
    # Some formats clear the tag block entirely on delete.
    class DroppingMP3(metadata.mp3_class):
        def delete(self, *args, **kwargs):
            super().delete(*args, **kwargs)
            self.tags = None

    monkeypatch.setattr(metadata, "mp3_class", DroppingMP3)
    metadata.set_id3_tags(mp3_file, {"title": "A Title", "artwork": [artwork()]})

    metadata.remove_id3_tags(mp3_file, preserve_artwork = True)
    tags = metadata.get_id3_tags(mp3_file, artwork_format = config.ImageFileType.PNG)

    assert tags["artwork"][0]["data"] == artwork()["data"]
