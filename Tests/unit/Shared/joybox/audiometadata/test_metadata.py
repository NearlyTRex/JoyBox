# Third-party imports
import pytest


###########################################################
# Choosing the format from the file
#
# The dispatcher picks the tag format from the extension; the wrong one fails
# to parse the container entirely.
###########################################################

@pytest.mark.parametrize("fixture", ["mp3_file", "m4a_file"])
def test_each_format_is_tagged_as_itself(metadata, request, fixture):
    audio_file = request.getfixturevalue(fixture)

    assert metadata.has_tags(audio_file) is False
    assert metadata.set_tags(audio_file, {"title": "A Title"}) is True
    assert metadata.get_tags(audio_file)["title"] == "A Title"
    assert metadata.has_tags(audio_file) is True
    assert metadata.remove_tags(audio_file) is True
    assert not metadata.get_tags(audio_file).get("title")
    assert metadata.get_file_info(audio_file)["path"] == audio_file


@pytest.mark.parametrize("extension", [".m4b", ".mp4", ".aac", ".M4A"])
def test_every_mp4_extension_reads_as_mp4(metadata, m4a_file, tmp_path, extension):
    renamed = tmp_path / ("track" + extension)
    (tmp_path / "track.m4a").rename(renamed)
    metadata.set_mp4_tags(str(renamed), {"title": "A Title"})

    assert metadata.get_tags(str(renamed))["title"] == "A Title"


def test_a_file_that_is_not_audio_is_reported_rather_than_raising(metadata, tmp_path):
    # A sweep over a mixed directory hands these in
    other = tmp_path / "notes.txt"
    other.write_text("not audio")

    assert metadata.get_tags(str(other)) is None
    assert metadata.has_tags(str(other)) is False
    assert metadata.set_tags(str(other), {"title": "A Title"}) is False
    assert metadata.remove_tags(str(other)) is False
    assert metadata.get_file_info(str(other)) is None


def test_a_missing_file_is_reported(metadata, tmp_path):
    absent = str(tmp_path / "absent.mp3")

    assert metadata.get_tags(absent) is None
    assert metadata.has_tags(absent) is False
    assert metadata.set_tags(absent, {"title": "A Title"}) is False
    assert metadata.remove_tags(absent) is False
    assert metadata.get_file_info(absent) is None
