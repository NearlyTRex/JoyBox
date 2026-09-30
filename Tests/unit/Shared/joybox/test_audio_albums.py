# Imports
import importlib
import json
import os

# Third-party imports
import pytest

# Local imports
from joybox import audio, audiometadata, config

pytestmark = pytest.mark.slow


###########################################################
# The album metadata pipeline against real files
#
# Tags are read off an album into a json file, hand-edited, and written back.
# The json is the only copy of what was there before, so a build that loses a
# track or an apply that writes it to the wrong file is unrecoverable.
###########################################################

# A silent MPEG-1 Layer III frame, repeated enough for mutagen to parse it
MP3_FRAME = b"\xff\xfb\x90\x00" + b"\x00" * 413

GENRE = config.AudioGenreType.members()[0]


@pytest.fixture(autouse = True)
def real_mutagen(monkeypatch):
    # The tag classes come from a vendored mutagen a hermetic run has no copy
    # of. The import is the seam; the tagging is what is under test.
    loaded = [
        importlib.import_module(name)
        for name in ("mutagen", "mutagen.mp3", "mutagen.id3", "mutagen.mp4")
    ]

    # Each handler imports all four in order, so the substitute hands them
    # back in the same order however many handlers are built.
    def sequenced(module_path, module_name):
        module = loaded[sequenced.index % len(loaded)]
        sequenced.index += 1
        return module

    sequenced.index = 0
    monkeypatch.setattr(
        audiometadata.modules, "import_python_module_package", sequenced)


@pytest.fixture
def library(tmp_path, monkeypatch):
    # A music tree and somewhere for the generated json to land.
    root = tmp_path / "Music"
    root.mkdir()
    metadata_root = tmp_path / "AudioMetadata"
    metadata_root.mkdir()

    def genre_dir(genre_type = None):
        if genre_type is None:
            return str(root)
        return str(root / genre_type.value)

    def metadata_file(metadata_type, genre_value, album_name, artist_name = None):
        parts = [part for part in [genre_value, artist_name] if part]
        directory = metadata_root.joinpath(*parts)
        directory.mkdir(parents = True, exist_ok = True)
        return str(directory / (album_name + ".json"))

    monkeypatch.setattr(audio.environment, "get_locker_music_dir", genre_dir)
    monkeypatch.setattr(audio.environment, "get_file_audio_metadata_file", metadata_file)
    return {"root": root, "metadata": metadata_root}


def make_album(library, album = "An Album", artist = None, tracks = ("01 - First.mp3", "02 - Second.mp3")):
    parts = [GENRE.value] + ([artist] if artist else []) + [album]
    album_dir = library["root"].joinpath(*parts)
    album_dir.mkdir(parents = True)
    for track in tracks:
        (album_dir / track).write_bytes(MP3_FRAME * 40)
    return album_dir


@pytest.fixture
def metadata():
    return audiometadata.AudioMetadata()


def tag(metadata, album_dir, filename, **tags):
    assert metadata.set_id3_tags(str(album_dir / filename), tags) is True


def built_json(library, album = "An Album", artist = None):
    parts = [GENRE.value] + ([artist] if artist else [])
    return library["metadata"].joinpath(*parts) / (album + ".json")


###########################################################
# Building the metadata file
###########################################################

def test_an_album_is_written_to_a_metadata_file(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "First")

    assert audio.build_audio_metadata_files(genre_type = GENRE) is True
    assert built_json(library).is_file()


def test_every_track_reaches_the_metadata_file(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "First")
    tag(metadata, album_dir, "02 - Second.mp3", title = "Second")

    audio.build_audio_metadata_files(genre_type = GENRE)
    with open(str(built_json(library))) as handle:
        data = json.load(handle)

    assert [track["filename"] for track in data["tracks"]] == \
        ["01 - First.mp3", "02 - Second.mp3"]


def test_a_tracks_tags_are_recorded(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "First", artist = "An Artist")

    audio.build_audio_metadata_files(genre_type = GENRE)
    with open(str(built_json(library))) as handle:
        data = json.load(handle)

    first = data["tracks"][0]["tags"]
    assert first["title"] == "First"
    assert first["artist"] == "An Artist"


def test_an_album_under_an_artist_is_filed_under_that_artist(library, metadata):
    # The artist folder is part of where the metadata lives, so two albums of
    # the same name by different artists do not collide.
    album_dir = make_album(library, artist = "An Artist")
    tag(metadata, album_dir, "01 - First.mp3", title = "First")

    audio.build_audio_metadata_files(genre_type = GENRE)

    assert built_json(library, artist = "An Artist").is_file()


def test_track_numbers_can_be_taken_from_the_running_order(library, metadata):
    # Downloaded tracks carry whatever number the source stamped on them,
    # which is usually the same one for every file.
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", track_number = "1")
    tag(metadata, album_dir, "02 - Second.mp3", track_number = "1")

    audio.build_audio_metadata_files(genre_type = GENRE, use_index_for_track_number = True)
    with open(str(built_json(library))) as handle:
        data = json.load(handle)

    assert [track["tags"]["track_number"] for track in data["tracks"]] == ["1", "2"]


def test_original_track_numbers_are_kept_by_default(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", track_number = "7")

    audio.build_audio_metadata_files(genre_type = GENRE)
    with open(str(built_json(library))) as handle:
        data = json.load(handle)

    assert data["tracks"][0]["tags"]["track_number"] == "7"


def test_a_forced_tag_overrides_what_the_file_carried(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", genre = "Whatever The Source Said")

    audio.build_audio_metadata_files(
        genre_type = GENRE, force_tags = {"genre": "Chosen Genre"})
    with open(str(built_json(library))) as handle:
        data = json.load(handle)

    assert data["tracks"][0]["tags"]["genre"] == "Chosen Genre"


def test_a_genre_with_no_albums_builds_nothing(library):
    assert audio.build_audio_metadata_files(genre_type = GENRE) is False


def test_an_album_with_no_audio_files_fails_the_build(library):
    album_dir = library["root"] / GENRE.value / "An Album"
    album_dir.mkdir(parents = True)
    (album_dir / "notes.txt").write_text("not audio")

    assert audio.build_audio_metadata_files(genre_type = GENRE) is False


###########################################################
# Applying the metadata file back
###########################################################

def test_metadata_is_written_back_onto_the_tracks(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "Original")
    tag(metadata, album_dir, "02 - Second.mp3", title = "Second")
    audio.build_audio_metadata_files(genre_type = GENRE)

    # Stand in for the hand edit the json file exists for
    path = built_json(library)
    with open(str(path)) as handle:
        data = json.load(handle)
    data["tracks"][0]["tags"]["title"] = "Corrected"
    with open(str(path), "w") as handle:
        json.dump(data, handle)

    assert audio.apply_audio_metadata_tags(genre_type = GENRE) is True
    assert metadata.get_id3_tags(str(album_dir / "01 - First.mp3"))["title"] == "Corrected"


def test_applying_leaves_the_other_tracks_as_they_were(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "First")
    tag(metadata, album_dir, "02 - Second.mp3", title = "Second")
    audio.build_audio_metadata_files(genre_type = GENRE)

    audio.apply_audio_metadata_tags(genre_type = GENRE)

    assert metadata.get_id3_tags(str(album_dir / "02 - Second.mp3"))["title"] == "Second"


def test_a_build_and_apply_round_trip_changes_nothing(library, metadata):
    # The pipeline is run repeatedly over the same library, so it has to be
    # stable when nothing was edited.
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "First", artist = "An Artist")
    audio.build_audio_metadata_files(genre_type = GENRE)
    audio.apply_audio_metadata_tags(genre_type = GENRE)

    tags = metadata.get_id3_tags(str(album_dir / "01 - First.mp3"))

    assert tags["title"] == "First"
    assert tags["artist"] == "An Artist"


def test_applying_without_a_metadata_file_is_refused(library, metadata):
    make_album(library)

    assert audio.apply_audio_metadata_tags(genre_type = GENRE) is False


def test_applying_to_a_genre_with_no_albums_is_refused(library):
    assert audio.apply_audio_metadata_tags(genre_type = GENRE) is False


def test_a_track_named_in_the_metadata_but_missing_fails_the_apply(library, metadata):
    # A renamed file would otherwise be skipped silently and left untagged.
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "First")
    audio.build_audio_metadata_files(genre_type = GENRE)
    os.remove(str(album_dir / "01 - First.mp3"))
    os.remove(str(album_dir / "02 - Second.mp3"))
    (album_dir / "03 - Renamed.mp3").write_bytes(MP3_FRAME * 40)

    assert audio.apply_audio_metadata_tags(genre_type = GENRE) is False


###########################################################
# Clearing tags
###########################################################

def test_an_albums_tags_are_cleared(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "First")

    assert audio.clear_audio_metadata_tags(genre_type = GENRE) is True
    assert not metadata.get_id3_tags(str(album_dir / "01 - First.mp3")).get("title")


def test_clearing_takes_every_track(library, metadata):
    album_dir = make_album(library)
    tag(metadata, album_dir, "01 - First.mp3", title = "First")
    tag(metadata, album_dir, "02 - Second.mp3", title = "Second")

    audio.clear_audio_metadata_tags(genre_type = GENRE)

    assert not metadata.get_id3_tags(str(album_dir / "02 - Second.mp3")).get("title")


def test_clearing_a_genre_with_no_albums_is_refused(library):
    assert audio.clear_audio_metadata_tags(genre_type = GENRE) is False
