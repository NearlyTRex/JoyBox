# Imports
import os
import pytest

# Local imports
from joybox import audio, config


###########################################################
# Audio library layout
#
# Albums live either directly under a genre or one level down under an artist.
# Getting the shape wrong tags the wrong files, or silently tags none.
###########################################################

@pytest.fixture
def music_root(tmp_path, monkeypatch):
    root = tmp_path / "Music"
    root.mkdir()

    def genre_dir(genre_type = None):
        if genre_type is None:
            return str(root)
        return str(root / genre_type.value)

    monkeypatch.setattr(audio.environment, "get_locker_music_dir", genre_dir)
    return root


GENRE = config.AudioGenreType.members()[0]


def make_album(root, *parts, tracks = ("01 - Track.mp3",)):
    album = root.joinpath(*parts)
    album.mkdir(parents = True, exist_ok = True)
    for track in tracks:
        (album / track).write_bytes(b"ID3")
    return album


###########################################################
# Finding albums
###########################################################

def test_a_missing_genre_directory_finds_nothing(music_root):
    assert audio.get_album_directories(GENRE) == []


def test_an_empty_genre_directory_finds_nothing(music_root):
    (music_root / GENRE.value).mkdir()

    assert audio.get_album_directories(GENRE) == []


def test_an_album_directly_under_the_genre_is_found(music_root):
    album = make_album(music_root, GENRE.value, "Some Album")

    assert audio.get_album_directories(GENRE) == [str(album)]


def test_an_artist_directory_yields_its_albums(music_root):
    # An artist folder holds albums, not tracks, so the albums are the targets.
    first = make_album(music_root, GENRE.value, "Some Artist", "First Album")
    second = make_album(music_root, GENRE.value, "Some Artist", "Second Album")

    found = audio.get_album_directories(GENRE)
    assert sorted(found) == sorted([str(first), str(second)])


def test_a_directory_holding_tracks_is_the_album(music_root):
    # Even with subfolders present, mp3 files here mean this is the album.
    album = make_album(music_root, GENRE.value, "Some Album")
    (album / "Extras").mkdir()

    assert audio.get_album_directories(GENRE) == [str(album)]


def test_a_directory_with_subfolders_and_no_tracks_descends(music_root):
    make_album(music_root, GENRE.value, "Some Artist", "First Album")

    found = audio.get_album_directories(GENRE)
    assert all(path.endswith("First Album") for path in found)


def test_mixed_layouts_are_both_found(music_root):
    flat = make_album(music_root, GENRE.value, "Flat Album")
    nested = make_album(music_root, GENRE.value, "Some Artist", "Nested Album")

    found = audio.get_album_directories(GENRE)
    assert sorted(found) == sorted([str(flat), str(nested)])


def test_loose_files_under_the_genre_are_not_albums(music_root):
    genre_dir = music_root / GENRE.value
    genre_dir.mkdir()
    (genre_dir / "stray.mp3").write_bytes(b"ID3")

    assert audio.get_album_directories(GENRE) == []


def test_an_uppercase_extension_still_marks_an_album(music_root):
    album = make_album(music_root, GENRE.value, "Some Album", tracks = ("01 - Track.MP3",))
    (album / "Extras").mkdir()

    assert audio.get_album_directories(GENRE) == [str(album)]


def test_a_named_album_narrows_the_search(music_root, monkeypatch):
    wanted = make_album(music_root, GENRE.value, "Wanted Album")
    make_album(music_root, GENRE.value, "Other Album")
    monkeypatch.setattr(
        audio.environment, "get_locker_music_album_dir",
        lambda **kwargs: str(wanted))

    assert audio.get_album_directories(GENRE, album_name = "Wanted Album") == [str(wanted)]


def test_a_named_album_that_is_missing_finds_nothing(music_root, monkeypatch):
    (music_root / GENRE.value).mkdir()
    monkeypatch.setattr(
        audio.environment, "get_locker_music_album_dir",
        lambda **kwargs: str(music_root / GENRE.value / "Absent"))

    assert audio.get_album_directories(GENRE, album_name = "Absent") == []


###########################################################
# Download archives
###########################################################

def test_an_archive_yields_its_video_ids(tmp_path):
    target = tmp_path / "archive.txt"
    target.write_text("youtube abc123\nyoutube def456\n")

    assert audio.get_archived_video_ids(str(target)) == {"abc123", "def456"}


def test_an_archive_id_is_the_last_field(tmp_path):
    # yt-dlp writes "<extractor> <id>", and the extractor is not the id.
    target = tmp_path / "archive.txt"
    target.write_text("youtube abc123\n")

    assert audio.get_archived_video_ids(str(target)) == {"abc123"}


def test_a_bare_id_is_read(tmp_path):
    target = tmp_path / "archive.txt"
    target.write_text("abc123\n")

    assert audio.get_archived_video_ids(str(target)) == {"abc123"}


def test_blank_archive_lines_are_skipped(tmp_path):
    target = tmp_path / "archive.txt"
    target.write_text("youtube abc123\n\n   \nyoutube def456\n")

    assert audio.get_archived_video_ids(str(target)) == {"abc123", "def456"}


def test_a_repeated_id_is_kept_once(tmp_path):
    target = tmp_path / "archive.txt"
    target.write_text("youtube abc123\nyoutube abc123\n")

    assert audio.get_archived_video_ids(str(target)) == {"abc123"}


def test_a_missing_archive_yields_nothing(tmp_path):
    assert audio.get_archived_video_ids(str(tmp_path / "absent.txt")) == set()


def test_no_archive_yields_nothing():
    assert audio.get_archived_video_ids(None) == set()


def test_an_empty_archive_yields_nothing(tmp_path):
    target = tmp_path / "archive.txt"
    target.write_text("")

    assert audio.get_archived_video_ids(str(target)) == set()


###########################################################
# Metadata action dispatch
###########################################################

@pytest.fixture
def actions(monkeypatch):
    calls = []
    for name in ["build_audio_metadata_files", "clear_audio_metadata_tags",
                 "apply_audio_metadata_tags"]:
        monkeypatch.setattr(
            audio, name,
            lambda _name = name, **kwargs: calls.append((_name, kwargs)) or True)
    return calls


@pytest.mark.parametrize("action,expected", [
    (config.AudioMetadataAction.TAG, "build_audio_metadata_files"),
    (config.AudioMetadataAction.CLEAR, "clear_audio_metadata_tags"),
    (config.AudioMetadataAction.APPLY, "apply_audio_metadata_tags"),
])
def test_each_action_reaches_its_handler(actions, action, expected):
    assert audio.run_metadata_action(action, GENRE) is True
    assert [name for name, _ in actions] == [expected]


def test_an_unknown_action_is_refused(actions):
    assert audio.run_metadata_action("not-an-action", GENRE) is False
    assert actions == []


def test_tagging_passes_its_options_through(actions):
    audio.run_metadata_action(
        config.AudioMetadataAction.TAG, GENRE,
        exclude_comments = True,
        use_index_for_track_number = True,
        force_tags = {"genre": "Audiobook"})
    kwargs = actions[0][1]

    assert kwargs["exclude_comments"] is True
    assert kwargs["use_index_for_track_number"] is True
    assert kwargs["force_tags"] == {"genre": "Audiobook"}


def test_clearing_passes_artwork_preservation_through(actions):
    audio.run_metadata_action(
        config.AudioMetadataAction.CLEAR, GENRE, preserve_artwork = True)

    assert actions[0][1]["preserve_artwork"] is True


def test_applying_passes_the_clear_flag_through(actions):
    audio.run_metadata_action(
        config.AudioMetadataAction.APPLY, GENRE, clear_existing = True)

    assert actions[0][1]["clear_existing"] is True


###########################################################
# Genre tagging policy
###########################################################

@pytest.fixture
def policy(monkeypatch):
    calls = []
    monkeypatch.setattr(audio, "get_album_directories",
                        lambda *args, **kwargs: ["/music/album"])
    for name in ["build_audio_metadata_files", "apply_audio_metadata_tags"]:
        monkeypatch.setattr(
            audio, name,
            lambda _name = name, **kwargs: calls.append((_name, kwargs)) or True)
    return calls


def kwargs_for(calls, name):
    return [entry for call_name, entry in calls if call_name == name][0]


def test_a_genre_with_no_albums_is_not_a_failure(monkeypatch):
    # Most genres are empty in a given library; that is not an error.
    monkeypatch.setattr(audio, "get_album_directories", lambda *args, **kwargs: [])

    assert audio.tag_genre_with_policy(GENRE) is True


def test_a_genre_with_no_albums_tags_nothing(monkeypatch, policy):
    monkeypatch.setattr(audio, "get_album_directories", lambda *args, **kwargs: [])
    audio.tag_genre_with_policy(GENRE)

    assert policy == []


def test_the_genre_tag_is_forced_to_the_folder(policy):
    # yt-dlp does not embed a genre, so the folder is the only source of truth.
    audio.tag_genre_with_policy(GENRE)

    assert kwargs_for(policy, "build_audio_metadata_files")["force_tags"]["genre"] == \
        GENRE.value


def test_comments_are_always_excluded(policy):
    audio.tag_genre_with_policy(GENRE)

    assert kwargs_for(policy, "build_audio_metadata_files")["exclude_comments"] is True


def test_extra_force_tags_are_merged(policy):
    audio.tag_genre_with_policy(GENRE, extra_force_tags = {"artist": "Someone"})
    forced = kwargs_for(policy, "build_audio_metadata_files")["force_tags"]

    assert forced["artist"] == "Someone"
    assert forced["genre"] == GENRE.value


def test_an_extra_tag_can_override_the_genre(policy):
    audio.tag_genre_with_policy(GENRE, extra_force_tags = {"genre": "Override"})

    assert kwargs_for(policy, "build_audio_metadata_files")["force_tags"]["genre"] == \
        "Override"


@pytest.mark.parametrize("genre_value", config.audio_track_index_genres)
def test_youtube_sourced_genres_renumber_by_index(policy, genre_value, monkeypatch):
    # yt-dlp embeds a uniform track number, so the file order is the only
    # correct numbering.
    genre = [entry for entry in config.AudioGenreType.members()
             if entry.value == genre_value][0]
    audio.tag_genre_with_policy(genre)

    assert kwargs_for(policy, "build_audio_metadata_files")["use_index_for_track_number"] \
        is True


def test_other_genres_keep_their_track_numbers(policy):
    genre = [entry for entry in config.AudioGenreType.members()
             if entry.value not in config.audio_track_index_genres]
    if not genre:
        pytest.skip("every genre renumbers by index")
    audio.tag_genre_with_policy(genre[0])

    assert kwargs_for(policy, "build_audio_metadata_files")["use_index_for_track_number"] \
        is False


def test_tags_are_applied_by_default(policy):
    audio.tag_genre_with_policy(GENRE)

    assert "apply_audio_metadata_tags" in [name for name, _ in policy]


def test_tags_can_be_built_without_applying(policy):
    # The sidecars are written for review before anything touches the audio.
    assert audio.tag_genre_with_policy(GENRE, apply_tags = False) is True
    assert [name for name, _ in policy] == ["build_audio_metadata_files"]


def test_a_failed_build_does_not_apply(monkeypatch, policy):
    monkeypatch.setattr(audio, "build_audio_metadata_files", lambda **kwargs: False)

    assert audio.tag_genre_with_policy(GENRE) is False
    assert [name for name, _ in policy] == []


###########################################################
# Running across genres
###########################################################

def test_every_genre_with_albums_is_handled(monkeypatch):
    monkeypatch.setattr(audio, "get_album_directories",
                        lambda genre_type, *args, **kwargs: ["/music/album"])
    handled = []

    assert audio.process_all_genres(lambda genre: handled.append(genre) or True) is True
    assert handled == config.AudioGenreType.members()


def test_a_genre_without_albums_is_skipped(monkeypatch):
    monkeypatch.setattr(
        audio, "get_album_directories",
        lambda genre_type, *args, **kwargs: ["/music/album"] if genre_type == GENRE else [])
    handled = []
    audio.process_all_genres(lambda genre: handled.append(genre) or True)

    assert handled == [GENRE]


def test_no_albums_anywhere_is_a_failure(monkeypatch):
    # Nothing to do across the whole library means the command did not work.
    monkeypatch.setattr(audio, "get_album_directories", lambda *args, **kwargs: [])

    assert audio.process_all_genres(lambda genre: True) is False


def test_one_failing_genre_fails_the_run(monkeypatch):
    monkeypatch.setattr(audio, "get_album_directories",
                        lambda *args, **kwargs: ["/music/album"])

    assert audio.process_all_genres(lambda genre: genre != GENRE) is False


def test_one_failing_genre_does_not_stop_the_others(monkeypatch):
    monkeypatch.setattr(audio, "get_album_directories",
                        lambda *args, **kwargs: ["/music/album"])
    handled = []

    def handler(genre):
        handled.append(genre)
        return genre != GENRE

    audio.process_all_genres(handler)
    assert handled == config.AudioGenreType.members()
