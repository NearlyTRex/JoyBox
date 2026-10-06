# Imports
import base64

# Third-party imports
import pytest

# Local imports
from audiometadata_helpers import PNG_PIXEL, artwork


###########################################################
# MP4 tags
###########################################################

def test_an_mp4_tag_is_written_and_read_back(metadata, m4a_file):
    assert metadata.set_mp4_tags(m4a_file, {"title": "A Title"}) is True
    assert metadata.get_mp4_tags(m4a_file)["title"] == "A Title"


TEXT_FIELDS = ["title", "artist", "album", "year", "genre", "album_artist", "composer",
               "comment", "encoder", "copyright", "description", "lyrics", "purchase_date",
               "sort_artist", "sort_album", "sort_title"]


@pytest.mark.parametrize("field", TEXT_FIELDS)
def test_every_text_field_survives_a_round_trip(metadata, m4a_file, field):
    metadata.set_mp4_tags(m4a_file, {field: "value-for-%s" % field})

    assert metadata.get_mp4_tags(m4a_file)[field] == "value-for-%s" % field


def test_no_two_mp4_fields_share_an_atom(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {field: "value-for-%s" % field for field in TEXT_FIELDS})

    tags = metadata.get_mp4_tags(m4a_file)

    assert len({tags[field] for field in TEXT_FIELDS}) == len(TEXT_FIELDS)


@pytest.mark.parametrize("field,written,read", [
    ("track_number", "3/12", "3/12"),
    ("track_number", 3, "3"),
    ("disc_number", "1/2", "1/2"),
    ("disc_number", "2", "2"),
    ("bpm", "120", "120"),
])
def test_numbers_are_stored_as_numbers(metadata, m4a_file, field, written, read):
    assert metadata.set_mp4_tags(m4a_file, {field: written}) is True
    assert metadata.get_mp4_tags(m4a_file)[field] == read


@pytest.mark.parametrize("field,value", [
    ("track_number", ""),
    ("track_number", "A1"),
    ("track_number", "1/"),
    ("disc_number", "one"),
    ("bpm", "120.5"),
])
def test_a_number_that_is_not_one_is_reported(metadata, m4a_file, field, value):
    metadata.set_mp4_tags(m4a_file, {"title": "Kept"})

    assert metadata.set_mp4_tags(m4a_file, {"title": "Lost", field: value}) is False
    assert metadata.get_mp4_tags(m4a_file)["title"] == "Kept"


def test_existing_tags_can_be_cleared_first(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"artist": "An Artist"})
    metadata.set_mp4_tags(m4a_file, {"title": "A Title"}, clear_existing = True)

    tags = metadata.get_mp4_tags(m4a_file)

    assert tags["title"] == "A Title"
    assert "artist" not in tags


def test_an_untagged_mp4_reads_as_empty(metadata, m4a_file):
    assert metadata.get_mp4_tags(m4a_file) == {}
    assert metadata.has_mp4_tags(m4a_file) is False


def test_a_tagged_mp4_reports_its_tags(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"title": "A Title"})

    assert metadata.has_mp4_tags(m4a_file) is True


def test_mp4_tags_can_be_removed(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"title": "A Title"})

    assert metadata.remove_mp4_tags(m4a_file) is True
    assert not metadata.get_mp4_tags(m4a_file).get("title")
    assert metadata.remove_mp4_tags(m4a_file) is True


###########################################################
# Pretend runs
###########################################################

def test_a_pretend_write_leaves_the_file_alone(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"title": "Real"})

    assert metadata.set_mp4_tags(m4a_file, {"title": "Pretend"}, pretend_run = True) is True
    assert metadata.get_mp4_tags(m4a_file)["title"] == "Real"


def test_a_pretend_removal_leaves_the_file_alone(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"title": "Real"})

    assert metadata.remove_mp4_tags(m4a_file, pretend_run = True) is True
    assert metadata.get_mp4_tags(m4a_file)["title"] == "Real"


###########################################################
# Artwork
###########################################################

@pytest.mark.parametrize("mime", ["image/png", "image/jpeg"])
def test_cover_art_keeps_its_format(metadata, m4a_file, mime):
    metadata.set_mp4_tags(m4a_file, {"artwork": [artwork(mime = mime)]})

    read = metadata.get_mp4_tags(m4a_file)["artwork"]

    assert read == [{"type": 3, "desc": "", "mime": mime, "data": artwork()["data"]}]


def test_cover_art_without_a_mime_is_stored_as_jpeg(metadata, m4a_file):
    cover = artwork()
    del cover["mime"]
    metadata.set_mp4_tags(m4a_file, {"artwork": [cover]})

    assert metadata.get_mp4_tags(m4a_file)["artwork"][0]["mime"] == "image/jpeg"


def test_cover_art_of_another_format_reads_as_jpeg(metadata, m4a_file):
    mp4 = metadata.mutagen_mp4
    audio = mp4.MP4(m4a_file)
    audio.add_tags()
    audio.tags["covr"] = [mp4.MP4Cover(PNG_PIXEL, imageformat = mp4.AtomDataType.GIF)]
    audio.save()

    assert metadata.get_mp4_tags(m4a_file)["artwork"][0]["mime"] == "image/jpeg"


def test_cover_art_can_be_left_out_of_a_read(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"artwork": [artwork()]})

    assert "artwork" not in metadata.get_mp4_tags(m4a_file, include_artwork = False)


def test_cover_art_can_be_kept_while_other_tags_are_removed(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"title": "A Title", "artwork": [artwork()]})

    metadata.remove_mp4_tags(m4a_file, preserve_artwork = True)
    tags = metadata.get_mp4_tags(m4a_file)

    assert base64.b64decode(tags["artwork"][0]["data"]) == PNG_PIXEL
    assert "title" not in tags


###########################################################
# Missing and unreadable files
###########################################################

def test_a_missing_mp4(metadata, tmp_path):
    absent = str(tmp_path / "absent.m4a")
    assert metadata.get_mp4_tags(absent) is None
    assert metadata.set_mp4_tags(absent, {"title": "A Title"}) is False
    assert metadata.remove_mp4_tags(absent) is False
    assert metadata.has_mp4_tags(absent) is False
    assert metadata.get_mp4_file_info(absent) is None


def test_a_file_that_is_not_an_mp4(metadata, tmp_path):
    other = tmp_path / "notes.m4a"
    other.write_text("not audio")
    assert metadata.get_mp4_tags(str(other)) is None
    assert metadata.set_mp4_tags(str(other), {"title": "A Title"}) is False
    assert metadata.remove_mp4_tags(str(other)) is False
    assert metadata.has_mp4_tags(str(other)) is False
    assert metadata.get_mp4_file_info(str(other)) is None


def test_mp4_file_info(metadata, m4a_file):
    info = metadata.get_mp4_file_info(m4a_file)

    assert info["path"] == m4a_file
    assert info["length"] == 1.0
    assert info["has_tags"] is False


def test_an_empty_cover_atom_reads_as_no_artwork(metadata, m4a_file):
    mp4 = metadata.mutagen_mp4
    audio = mp4.MP4(m4a_file)
    audio.add_tags()
    audio.tags["covr"] = []
    audio.tags["\xa9nam"] = []
    audio.save()

    assert metadata.get_mp4_tags(m4a_file) == {}


def test_an_empty_artwork_list_writes_no_cover(metadata, m4a_file):
    metadata.set_mp4_tags(m4a_file, {"title": "A Title", "artwork": []})

    assert "covr" not in metadata.mutagen_mp4.MP4(m4a_file).tags


def test_kept_cover_art_is_restored_when_removal_drops_the_tag_block(metadata, m4a_file, monkeypatch):
    # Some formats clear the tag block entirely on delete.
    class DroppingMP4(metadata.mp4_class):
        def delete(self, *args, **kwargs):
            super().delete(*args, **kwargs)
            self.tags = None

    monkeypatch.setattr(metadata, "mp4_class", DroppingMP4)
    metadata.set_mp4_tags(m4a_file, {"title": "A Title", "artwork": [artwork()]})

    metadata.remove_mp4_tags(m4a_file, preserve_artwork = True)

    assert metadata.get_mp4_tags(m4a_file)["artwork"][0]["data"] == artwork()["data"]
