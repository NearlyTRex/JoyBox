# Imports
import pathlib

# Third-party imports
import pytest

# Local imports
from joybox import audio, config


###########################################################
# Channel audio downloads
#
# Each channel is enumerated, the videos not yet in its download archive are
# fetched in batches, and every batch is uploaded to the locker before the
# next starts. A batch that is lost between download and upload is gone, and
# an upload of the wrong folder fills the locker with thumbnails.
###########################################################

GENRE = config.AudioGenreType.STORY
CHANNEL_URL = "https://www.youtube.com/@SomeChannel"
OTHER_URL = "https://www.youtube.com/@OtherChannel"
CHANNELS = [
    {"name": "Some Channel", "url": CHANNEL_URL},
    {"name": "Other Channel", "url": OTHER_URL}]
MUSIC_DIR = "/locker/Music/Story/Some Channel"


###########################################################
# Collecting and uploading a working directory
###########################################################

class Backups:
    def __init__(self):
        self.calls = []
        self.result = True

    def backup(self, **kwargs):
        contents = sorted(path.name for path in pathlib.Path(kwargs["src"]).iterdir())
        self.calls.append((kwargs, contents))
        return self.result


@pytest.fixture
def backups(monkeypatch):
    state = Backups()
    monkeypatch.setattr(audio.locker, "backup", state.backup)
    monkeypatch.setattr(
        audio.locker, "convert_to_relative_path", lambda path: "Music/" + path.rsplit("/", 1)[-1])
    return state


def test_a_missing_working_directory_has_nothing_to_upload(tmp_path, backups):
    assert audio.collect_and_upload_audio(str(tmp_path / "absent"), MUSIC_DIR) is True
    assert backups.calls == []


def test_audio_is_collected_and_uploaded(tmp_path, backups):
    (tmp_path / "Episode.mp3").write_bytes(b"ID3")
    (tmp_path / "Episode.webp").write_bytes(b"RIFF")

    assert audio.collect_and_upload_audio(str(tmp_path), MUSIC_DIR) is True
    kwargs, contents = backups.calls[0]
    assert contents == ["Episode.mp3"]
    assert kwargs["src"] == str(tmp_path / "audio_only")
    assert kwargs["dest_rel_path"] == "Music/Some Channel"
    assert kwargs["skip_existing"] is True


def test_uploaded_audio_is_removed_and_the_rest_kept(tmp_path, backups):
    (tmp_path / "Episode.MP3").write_bytes(b"ID3")
    (tmp_path / "Episode.webp").write_bytes(b"RIFF")
    audio.collect_and_upload_audio(str(tmp_path), MUSIC_DIR)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["Episode.webp"]


@pytest.mark.parametrize("name", ["a.mp3", "a.m4a", "a.wav", "a.flac", "a.ogg"])
def test_every_audio_format_is_collected(tmp_path, backups, name):
    (tmp_path / name).write_bytes(b"\x00")
    audio.collect_and_upload_audio(str(tmp_path), MUSIC_DIR)

    assert not (tmp_path / name).exists()


def test_a_directory_named_like_audio_is_not_collected(tmp_path, backups):
    (tmp_path / "folder.mp3").mkdir()

    assert audio.collect_and_upload_audio(str(tmp_path), MUSIC_DIR) is True
    assert (tmp_path / "folder.mp3").is_dir()
    assert not (tmp_path / "audio_only").exists()


def test_a_directory_without_audio_uploads_nothing(tmp_path, monkeypatch):
    (tmp_path / "Episode.webp").write_bytes(b"RIFF")
    monkeypatch.setattr(audio.locker, "backup", lambda **kwargs: pytest.fail("uploaded"))

    assert audio.collect_and_upload_audio(str(tmp_path), MUSIC_DIR) is True


def test_audio_left_by_an_interrupted_upload_is_retried(tmp_path, backups):
    # The top level is empty, but the previous run's collected audio is pending.
    pending = tmp_path / "audio_only"
    pending.mkdir()
    (pending / "Earlier.mp3").write_bytes(b"ID3")
    (tmp_path / "Later.mp3").write_bytes(b"ID3")

    assert audio.collect_and_upload_audio(str(tmp_path), MUSIC_DIR) is True
    assert backups.calls[0][1] == ["Earlier.mp3", "Later.mp3"]
    assert not pending.exists()


def test_an_empty_pending_directory_uploads_nothing(tmp_path, monkeypatch):
    (tmp_path / "audio_only").mkdir()
    (tmp_path / "audio_only" / "cover.jpg").write_bytes(b"JPG")
    monkeypatch.setattr(audio.locker, "backup", lambda **kwargs: pytest.fail("uploaded"))

    assert audio.collect_and_upload_audio(str(tmp_path), MUSIC_DIR) is True


def test_a_failed_upload_keeps_the_audio(tmp_path, backups):
    backups.result = False
    (tmp_path / "Episode.mp3").write_bytes(b"ID3")

    assert audio.collect_and_upload_audio(str(tmp_path), MUSIC_DIR) is False
    assert (tmp_path / "audio_only" / "Episode.mp3").exists()


###########################################################
# Downloading channels
###########################################################

class Downloads:
    def __init__(self):
        self.videos = {}
        self.archived = set()
        self.downloads = []
        self.uploads = []
        self.removed = []
        self.made = []
        self.download_result = True
        self.upload_result = True
        self.temp_result = True
        self.temp_count = 0


@pytest.fixture
def downloads(monkeypatch):
    state = Downloads()
    monkeypatch.setattr(audio.config, "audio_download_batch_size", 0)
    monkeypatch.setattr(audio.config, "audio_download_oldest_first", False)
    monkeypatch.setattr(
        audio.environment, "get_file_audio_metadata_archive_file",
        lambda genre_type, name: "/archive/" + name + ".txt")
    monkeypatch.setattr(
        audio.environment, "get_locker_music_album_dir",
        lambda album_name, locker_type, genre_type: "/locker/" + album_name)
    monkeypatch.setattr(
        audio.fileops, "make_directory", lambda src, **kwargs: state.made.append(src))
    monkeypatch.setattr(
        audio.fileops, "remove_directory", lambda src, **kwargs: state.removed.append(src))

    def create_temporary_directory(**kwargs):
        state.temp_count += 1
        return state.temp_result, "/tmp/batch%d" % state.temp_count

    monkeypatch.setattr(audio.fileops, "create_temporary_directory", create_temporary_directory)
    monkeypatch.setattr(
        audio.google, "get_playlist_video_ids",
        lambda video_url, **kwargs: state.videos.get(video_url, []))
    monkeypatch.setattr(audio, "get_archived_video_ids", lambda archive: state.archived)

    def download_video(**kwargs):
        state.downloads.append(kwargs)
        return state.download_result

    def collect(work_dir, music_dir, **kwargs):
        state.uploads.append((work_dir, music_dir, kwargs))
        return state.upload_result

    monkeypatch.setattr(audio.google, "download_video", download_video)
    monkeypatch.setattr(audio, "collect_and_upload_audio", collect)
    return state


def run(**kwargs):
    kwargs.setdefault("channels", CHANNELS[:1])
    return audio.download_channel_audio_files(genre_type = GENRE, **kwargs)


def targets(state):
    return [entry["video_url"] for entry in state.downloads]


def test_only_new_videos_are_downloaded(downloads):
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a"), ("b", "https://v/b"), ("c", None)]
    downloads.archived = {"b"}

    assert run() is True
    assert targets(downloads) == [["https://v/a", "https://www.youtube.com/watch?v=c"]]


def test_a_download_carries_the_channel_archive(downloads):
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]
    run(cookie_source = "firefox")
    call = downloads.downloads[0]

    assert call["download_archive"] == "/archive/Some Channel.txt"
    assert call["audio_only"] is True
    assert call["cookie_source"] == "firefox"
    assert call["concurrent_fragments"] == config.audio_download_concurrent_fragments


def test_a_channel_that_is_up_to_date_downloads_nothing(downloads):
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]
    downloads.archived = {"a"}

    assert run() is True
    assert downloads.downloads == []
    assert downloads.made == ["/locker/Some Channel"]


def test_an_unlistable_channel_is_downloaded_whole(downloads):
    assert run() is True
    assert targets(downloads) == [CHANNEL_URL]


def test_new_videos_are_split_into_batches(downloads, monkeypatch):
    monkeypatch.setattr(audio.config, "audio_download_batch_size", 2)
    downloads.videos[CHANNEL_URL] = [(v, "https://v/" + v) for v in "abcde"]

    assert run() is True
    assert targets(downloads) == [
        ["https://v/a", "https://v/b"], ["https://v/c", "https://v/d"], ["https://v/e"]]
    assert [work_dir for work_dir, _, _ in downloads.uploads] == \
        ["/tmp/batch1", "/tmp/batch2", "/tmp/batch3"]


def test_each_temporary_batch_directory_is_removed(downloads, monkeypatch):
    monkeypatch.setattr(audio.config, "audio_download_batch_size", 1)
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a"), ("b", "https://v/b")]
    run()

    assert downloads.removed == ["/tmp/batch1", "/tmp/batch2"]


def test_a_batch_is_uploaded_to_the_channel_music_dir(downloads):
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]
    run(locker_type = config.LockerType.LOCAL)
    _, music_dir, kwargs = downloads.uploads[0]

    assert music_dir == "/locker/Some Channel"
    assert kwargs["locker_type"] == config.LockerType.LOCAL


@pytest.mark.parametrize("oldest_first,expected", [
    (True, ["https://v/b", "https://v/a"]),
    (False, ["https://v/a", "https://v/b"]),
])
def test_the_download_order_can_be_forced(downloads, oldest_first, expected):
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a"), ("b", "https://v/b")]
    run(oldest_first = oldest_first)

    assert targets(downloads) == [expected]


def test_the_download_order_defaults_to_the_config(downloads, monkeypatch):
    monkeypatch.setattr(audio.config, "audio_download_oldest_first", True)
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a"), ("b", "https://v/b")]
    run()

    assert targets(downloads) == [["https://v/b", "https://v/a"]]


def test_every_channel_is_downloaded(downloads):
    assert run(channels = CHANNELS) is True
    assert targets(downloads) == [CHANNEL_URL, OTHER_URL]


@pytest.mark.parametrize("query", ["other channel", "  Other Channel  ", "other"])
def test_one_channel_can_be_picked_by_name(downloads, query):
    assert run(channels = CHANNELS, channel_name = query) is True
    assert targets(downloads) == [OTHER_URL]


def test_an_exact_name_wins_over_a_partial_match(downloads):
    channels = [{"name": "Story Time Extra", "url": OTHER_URL}, {"name": "Story Time", "url": CHANNEL_URL}]

    assert run(channels = channels, channel_name = "story time") is True
    assert targets(downloads) == [CHANNEL_URL]


def test_an_unknown_channel_name_is_refused(downloads):
    assert run(channels = CHANNELS, channel_name = "Nobody") is False
    assert downloads.downloads == []


def test_a_failed_temporary_directory_stops_the_run(downloads):
    downloads.temp_result = False
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]

    assert run() is False
    assert downloads.downloads == []


def test_a_failed_download_stops_and_cleans_up(downloads):
    downloads.download_result = False
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]

    assert run(channels = CHANNELS) is False
    assert downloads.uploads == []
    assert downloads.removed == ["/tmp/batch1"]
    assert len(downloads.downloads) == 1


def test_a_failed_upload_stops_and_cleans_up(downloads):
    downloads.upload_result = False
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]

    assert run(channels = CHANNELS) is False
    assert downloads.removed == ["/tmp/batch1"]
    assert len(downloads.downloads) == 1


###########################################################
# Resumable downloads into an output path
###########################################################

def test_an_output_path_is_resumed_before_downloading(downloads):
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]

    assert run(output_path = "/work") is True
    assert "/work/Some Channel" in downloads.made
    assert [work_dir for work_dir, _, _ in downloads.uploads] == \
        ["/work/Some Channel", "/work/Some Channel"]
    assert downloads.downloads[0]["output_dir"] == "/work/Some Channel"


def test_an_output_path_is_kept(downloads, monkeypatch):
    monkeypatch.setattr(audio.config, "audio_download_batch_size", 1)
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a"), ("b", "https://v/b")]
    run(output_path = "/work")

    assert downloads.removed == []
    assert downloads.temp_count == 0


def test_a_failed_resume_stops_before_downloading(downloads):
    downloads.upload_result = False
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]

    assert run(output_path = "/work") is False
    assert downloads.downloads == []


def test_a_failed_download_keeps_the_output_path(downloads):
    downloads.download_result = False
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]

    assert run(output_path = "/work") is False
    assert downloads.removed == []


def test_a_failed_upload_keeps_the_output_path(downloads, monkeypatch):
    downloads.videos[CHANNEL_URL] = [("a", "https://v/a")]
    results = iter([True, False])
    monkeypatch.setattr(
        audio, "collect_and_upload_audio", lambda work_dir, music_dir, **kwargs: next(results))

    assert run(output_path = "/work") is False
    assert downloads.removed == []


###########################################################
# Genre shortcuts
###########################################################

@pytest.mark.parametrize("func,channels_name,genre", [
    (audio.download_story_audio_files, "story_channels", config.AudioGenreType.STORY),
    (audio.download_asmr_audio_files, "asmr_channels", config.AudioGenreType.ASMR),
])
def test_each_genre_downloads_its_channels(monkeypatch, func, channels_name, genre):
    calls = []
    monkeypatch.setattr(
        audio, "download_channel_audio_files", lambda **kwargs: calls.append(kwargs) or True)

    assert func(channel_name = "Some", output_path = "/work") is True
    assert calls[0]["channels"] is getattr(config, channels_name)
    assert calls[0]["genre_type"] == genre
    assert calls[0]["channel_name"] == "Some"
    assert calls[0]["output_path"] == "/work"
