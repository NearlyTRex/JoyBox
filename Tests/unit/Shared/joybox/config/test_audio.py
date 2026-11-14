# Imports
import urllib.parse

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import google
from joybox.config import audio

ALL_CHANNELS = audio.story_channels + audio.asmr_channels
CHANNEL_IDS = [channel["name"] for channel in ALL_CHANNELS]
CHANNEL_HOSTS = {"www.youtube.com", "rumble.com"}


###########################################################
# Channels
###########################################################

@pytest.mark.parametrize("channel", ALL_CHANNELS, ids = CHANNEL_IDS)
def test_channel_has_exactly_a_name_and_url(channel):
    assert set(channel) == {"name", "url"}
    assert channel["name"].strip() == channel["name"] != ""


@pytest.mark.parametrize("channel", ALL_CHANNELS, ids = CHANNEL_IDS)
def test_channel_url_is_https_on_a_supported_host(channel):
    parsed = urllib.parse.urlparse(channel["url"])
    assert parsed.scheme == "https"
    assert parsed.netloc in CHANNEL_HOSTS
    assert parsed.path.strip("/") != ""


@pytest.mark.parametrize("field", ["name", "url"])
def test_channel_fields_are_unique_across_genres(field):
    values = [channel[field] for channel in ALL_CHANNELS]
    assert len(values) == len(set(values))


###########################################################
# Download settings
###########################################################

def test_batch_size_is_a_non_negative_int():
    assert isinstance(audio.audio_download_batch_size, int)
    assert audio.audio_download_batch_size >= 0


def test_concurrent_fragments_is_within_the_download_clamp():
    assert isinstance(audio.audio_download_concurrent_fragments, int)
    assert 1 <= audio.audio_download_concurrent_fragments <= google.MAX_CONCURRENT_FRAGMENTS


###########################################################
# Track index genres
###########################################################

@pytest.mark.parametrize("genre", audio.audio_track_index_genres)
def test_track_index_genre_is_an_audio_genre_value(genre):
    assert genre in config.AudioGenreType.values()


def test_track_index_genres_are_unique():
    assert len(audio.audio_track_index_genres) == len(set(audio.audio_track_index_genres))


@pytest.mark.parametrize("channels, genre", [
    (audio.story_channels, config.AudioGenreType.STORY),
    (audio.asmr_channels, config.AudioGenreType.ASMR)
], ids = ["story", "asmr"])
def test_downloaded_genres_renumber_tracks_by_index(channels, genre):
    assert channels
    assert genre.value in audio.audio_track_index_genres
