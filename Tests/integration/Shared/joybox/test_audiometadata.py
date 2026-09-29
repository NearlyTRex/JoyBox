# Imports
import base64
import importlib
import shutil
import subprocess

# Third-party imports
import pytest

# Local imports
from joybox import audiometadata

pytestmark = pytest.mark.slow


###########################################################
# Audio tags on a real encoder's output
#
# The unit tests tag hand-built containers with no audio in them. These run
# the same calls on an AAC file ffmpeg wrote, where the tags share the file
# with real sample tables and the encoder's own atoms.
###########################################################

# A one pixel PNG, for the cover art
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
def m4a_file(tmp_path):
    if not shutil.which("ffmpeg"):
        pytest.skip("ffmpeg is not installed")
    target = str(tmp_path / "track.m4a")
    result = subprocess.run([
        "ffmpeg", "-loglevel", "error", "-y",
        "-f", "lavfi", "-i", "anullsrc=r=44100:cl=mono",
        "-t", "0.2", "-c:a", "aac", target,
    ], capture_output = True, check = False)
    assert result.returncode == 0, result.stderr.decode()
    return target


###########################################################
# MP4 tags
###########################################################

def test_tags_and_cover_art_survive_a_round_trip(metadata, m4a_file):
    cover = {"data": base64.b64encode(PNG_PIXEL).decode("ascii"), "mime": "image/png", "type": 3, "desc": ""}

    assert metadata.set_tags(m4a_file, {"title": "A Title", "track_number": "2/9", "artwork": [cover]}) is True
    tags = metadata.get_tags(m4a_file)

    assert tags["title"] == "A Title"
    assert tags["track_number"] == "2/9"
    assert tags["artwork"][0]["data"] == cover["data"]


def test_an_mp4_with_its_tags_removed_has_none(metadata, m4a_file):
    # The encoder stamps its own tag, so "untagged" means after a removal.
    assert metadata.has_tags(m4a_file) is True
    assert metadata.remove_tags(m4a_file) is True
    assert metadata.has_tags(m4a_file) is False


def test_an_mp4_reports_its_stream(metadata, m4a_file):
    info = metadata.get_file_info(m4a_file)

    assert info["sample_rate"] == 44100
    assert info["channels"] == 1
    assert 0.1 < info["length"] < 0.5
