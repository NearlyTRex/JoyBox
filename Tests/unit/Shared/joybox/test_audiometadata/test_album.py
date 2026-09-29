# Imports
import os

# Local imports
from joybox import config
from audiometadata_helpers import MP3_FRAME, build_m4a, artwork

GENRE = config.AudioGenreType.REGULAR


def make_album(root, names):
    album = root / "Artist" / "Album"
    os.makedirs(album)
    for name in names:
        (album / name).write_bytes(build_m4a() if name.endswith(".m4a") else MP3_FRAME * 40)
    (album / "cover.txt").write_text("not a track")
    return str(album)


def track(album, name):
    return os.path.join(album, name)


###########################################################
# Reading an album
###########################################################

def test_an_album_reads_every_track_in_name_order(metadata, tmp_path):
    album = make_album(tmp_path, ["02.mp3", "01.m4a"])
    metadata.set_tags(track(album, "01.m4a"), {"title": "One", "artist": "Band", "year": "1999"})
    metadata.set_tags(track(album, "02.mp3"), {"title": "Two", "artist": "Band"})

    result = metadata.get_album_tags(album, GENRE)

    assert result["album_path"] == "Album"
    assert result["total_tracks"] == 2
    assert [t["filename"] for t in result["tracks"]] == ["01.m4a", "02.mp3"]
    assert [t["tags"]["title"] for t in result["tracks"]] == ["One", "Two"]
    assert result["album_info"] == {
        "album": "Album", "album_artist": "Band", "artist": "Band", "year": "1999", "genre": "Regular"}


def test_missing_album_fields_come_from_the_folders(metadata, tmp_path):
    # yt-dlp does not embed these, and apply writes whatever is filled here
    album = make_album(tmp_path, ["01.mp3"])
    metadata.set_tags(track(album, "01.mp3"), {"title": "One", "artist": "Band", "album": ""})

    result = metadata.get_album_tags(album, GENRE)
    tags = result["tracks"][0]["tags"]

    assert tags["album"] == "Album"
    assert tags["album_artist"] == "Band"
    assert result["album_info"]["album"] == "Album"


def test_a_track_without_an_artist_gets_no_album_artist(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3"])
    metadata.set_tags(track(album, "01.mp3"), {"title": "One"})

    assert "album_artist" not in metadata.get_album_tags(album, GENRE)["tracks"][0]["tags"]


def test_track_numbers_fill_in_from_the_order(metadata, tmp_path):
    album = make_album(tmp_path, ["a.mp3", "b.mp3"])
    metadata.set_tags(track(album, "a.mp3"), {"track_number": "7"})

    numbers = [t["tags"]["track_number"] for t in metadata.get_album_tags(album, GENRE)["tracks"]]

    assert numbers == ["7", "2"]


def test_track_numbers_can_come_from_the_order_alone(metadata, tmp_path):
    # yt-dlp embeds the same bogus number in every track
    album = make_album(tmp_path, ["a.mp3", "b.mp3"])
    for name in ["a.mp3", "b.mp3"]:
        metadata.set_tags(track(album, name), {"track_number": "1"})

    result = metadata.get_album_tags(album, GENRE, use_index_for_track_number = True)

    assert [t["tags"]["track_number"] for t in result["tracks"]] == ["1", "2"]


def test_forced_tags_win_everywhere(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3"])
    metadata.set_tags(track(album, "01.mp3"), {"genre": "Pop", "artist": "Band"})

    result = metadata.get_album_tags(album, GENRE, force_tags = {"genre": "Regular", "title": "Forced"})

    assert result["tracks"][0]["tags"]["genre"] == "Regular"
    assert result["tracks"][0]["tags"]["title"] == "Forced"
    assert result["album_info"]["genre"] == "Regular"


def test_the_genre_falls_back_to_the_genre_type(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3"])

    assert metadata.get_album_tags(album, GENRE)["album_info"]["genre"] == "Regular"
    assert metadata.get_album_tags(album, None)["album_info"]["genre"] == ""


def test_album_artwork_comes_from_the_first_track(metadata, tmp_path):
    album = make_album(tmp_path, ["01.m4a", "02.m4a", "03.m4a"])
    metadata.set_tags(track(album, "01.m4a"), {"artwork": [artwork(data = b"front")]})
    metadata.set_tags(track(album, "02.m4a"), {"artwork": [artwork(data = b"front")]})
    metadata.set_tags(track(album, "03.m4a"), {"artwork": [artwork(data = b"other")]})

    result = metadata.get_album_tags(album, GENRE)

    assert result["album_artwork"]["data"] == artwork(data = b"front")["data"]
    assert all("artwork" not in t for t in result["tracks"])
    assert all("artwork" not in t["tags"] for t in result["tracks"])


def test_differing_track_artwork_can_be_kept(metadata, tmp_path):
    album = make_album(tmp_path, ["01.m4a", "02.m4a"])
    metadata.set_tags(track(album, "01.m4a"), {"artwork": [artwork(data = b"front")]})
    metadata.set_tags(track(album, "02.m4a"), {"artwork": [artwork(data = b"other")]})

    tracks = metadata.get_album_tags(album, GENRE, store_individual_artwork = True)["tracks"]

    assert "artwork" not in tracks[0]
    assert tracks[1]["artwork"]["data"] == artwork(data = b"other")["data"]


def test_an_unreadable_track_is_left_out(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3"])
    (tmp_path / "Artist" / "Album" / "02.mp3").write_text("not audio")

    assert metadata.get_album_tags(album, GENRE)["total_tracks"] == 1


def test_an_album_needs_a_folder_of_tracks(metadata, tmp_path):
    os.makedirs(tmp_path / "empty")
    assert metadata.get_album_tags(str(tmp_path / "missing"), GENRE) is None
    assert metadata.get_album_tags(str(tmp_path / "empty"), GENRE) is None


###########################################################
# Writing an album
###########################################################

def test_read_tags_apply_back_onto_the_album(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3", "02.m4a"])
    metadata.set_tags(track(album, "01.mp3"), {"title": "One", "artwork": [artwork(data = b"front")]})
    data = metadata.get_album_tags(album, GENRE)
    data["tracks"][1]["tags"]["title"] = "Two"
    data["tracks"][1]["artwork"] = artwork(data = b"own")

    assert metadata.set_album_tags(album, data) is True

    assert metadata.get_tags(track(album, "02.m4a"))["title"] == "Two"
    assert metadata.get_tags(track(album, "02.m4a"))["artwork"][0]["data"] == artwork(data = b"own")["data"]
    assert metadata.get_tags(track(album, "01.mp3"))["album"] == "Album"


def test_album_artwork_goes_on_every_track(metadata, tmp_path):
    album = make_album(tmp_path, ["01.m4a"])
    data = {"tracks": [{"filename": "01.m4a", "tags": {"title": "One"}}], "album_artwork": artwork()}

    assert metadata.set_album_tags(album, data) is True
    assert metadata.get_tags(track(album, "01.m4a"))["artwork"][0]["data"] == artwork()["data"]


def test_writing_an_album_stops_at_a_missing_or_failing_track(metadata, tmp_path):
    album = make_album(tmp_path, ["01.m4a"])

    assert metadata.set_album_tags(album, {"tracks": [{"filename": "absent.mp3", "tags": {}}]}) is False
    assert metadata.set_album_tags(album, {"tracks": [{"filename": "01.m4a", "tags": {"bpm": "fast"}}]}) is False


def test_writing_an_album_needs_a_folder_and_tracks(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3"])
    assert metadata.set_album_tags(str(tmp_path / "missing"), {"tracks": []}) is False
    assert metadata.set_album_tags(album, {}) is False


def test_a_pretend_album_write_changes_nothing(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3", "02.m4a"])
    data = {"tracks": [{"filename": name, "tags": {"title": "Pretend"}} for name in ["01.mp3", "02.m4a"]]}

    assert metadata.set_album_tags(album, data, pretend_run = True) is True
    assert metadata.has_tags(track(album, "01.mp3")) is False
    assert metadata.has_tags(track(album, "02.m4a")) is False


###########################################################
# Clearing an album
###########################################################

def test_clearing_an_album_strips_every_track(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3", "02.m4a"])
    for name in ["01.mp3", "02.m4a"]:
        metadata.set_tags(track(album, name), {"title": "A Title"})

    assert metadata.clear_album_tags(album) is True
    assert metadata.has_tags(track(album, "01.mp3")) is False
    assert metadata.has_tags(track(album, "02.m4a")) is False


def test_a_pretend_clear_changes_nothing(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3", "02.m4a"])
    for name in ["01.mp3", "02.m4a"]:
        metadata.set_tags(track(album, name), {"title": "A Title"})

    assert metadata.clear_album_tags(album, pretend_run = True) is True
    assert metadata.get_tags(track(album, "01.mp3"))["title"] == "A Title"
    assert metadata.get_tags(track(album, "02.m4a"))["title"] == "A Title"


def test_clearing_stops_at_a_failing_track(metadata, tmp_path):
    album = make_album(tmp_path, ["01.mp3"])
    (tmp_path / "Artist" / "Album" / "02.mp3").write_text("not audio")

    assert metadata.clear_album_tags(album) is False
    assert metadata.clear_album_tags(str(tmp_path / "missing")) is False
