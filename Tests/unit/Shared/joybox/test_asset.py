# Imports
import pytest

# Local imports
from joybox import asset, config


###########################################################
# Metadata assets
#
# Box art, screenshots and videos fetched for the collection. Exif data from a
# scraped image carries camera and location fields into the archive, so the
# clean step is not optional.
###########################################################

@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(asset.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(asset.programs, "get_tool_program", lambda name: "/tools/exiftool")
    return "/tools/exiftool"


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(asset.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(asset.programs, "get_tool_program", lambda name: None)


###########################################################
# Exif cleaning
###########################################################

def test_cleaning_strips_every_tag(installed, recording_command):
    asset.clean_exif_data("/assets/boxfront.jpg")

    assert "-All=" in recording_command.only()


def test_cleaning_overwrites_in_place(installed, recording_command):
    # Without this exiftool leaves a _original copy beside the asset, which
    # then gets archived too.
    asset.clean_exif_data("/assets/boxfront.jpg")

    assert "-overwrite_original" in recording_command.only()


def test_cleaning_names_the_asset(installed, recording_command):
    asset.clean_exif_data("/assets/boxfront.jpg")

    assert recording_command.only()[-1] == "/assets/boxfront.jpg"


def test_cleaning_recurses(installed, recording_command):
    asset.clean_exif_data("/assets")

    assert "-r" in recording_command.only()


def test_cleaning_blocks_on_the_tool(installed, recording_command):
    asset.clean_exif_data("/assets/boxfront.jpg")

    assert "/tools/exiftool" in recording_command.options().get_blocking_processes()


def test_cleaning_without_the_tool_reports_failure(missing, recording_command):
    assert asset.clean_exif_data("/assets/boxfront.jpg") is False
    assert recording_command.ran() is False


def test_a_failed_clean_is_reported(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert asset.clean_exif_data("/assets/boxfront.jpg") is False


def test_a_successful_clean_is_reported(installed, recording_command):
    assert asset.clean_exif_data("/assets/boxfront.jpg") is True


def test_pretending_still_builds_the_clean_command(installed, recording_command):
    asset.clean_exif_data("/assets/boxfront.jpg", pretend_run = True)

    assert recording_command.calls[0]["kwargs"].get("pretend_run") is True


###########################################################
# Downloading
###########################################################

@pytest.fixture
def downloads(monkeypatch):
    calls = []
    monkeypatch.setattr(
        asset.network, "download_url",
        lambda **kwargs: calls.append(("network", kwargs)) or True)
    monkeypatch.setattr(
        asset.google, "download_video",
        lambda **kwargs: calls.append(("google", kwargs)) or True)
    return calls


IMAGE_TYPES = [entry for entry in config.AssetType.members()
               if entry != config.AssetType.VIDEO]


@pytest.mark.parametrize("asset_type", IMAGE_TYPES)
def test_an_image_asset_is_downloaded_directly(downloads, asset_type):
    asset.download_asset("https://example.com/art.jpg", "/assets/art.jpg", asset_type)

    assert [name for name, _ in downloads] == ["network"]


def test_a_youtube_video_uses_the_video_downloader(downloads):
    # A plain fetch of a watch page saves the html, not the video.
    asset.download_asset(
        "https://www.youtube.com/watch?v=abc123", "/assets/video.mp4",
        config.AssetType.VIDEO)

    assert [name for name, _ in downloads] == ["google"]


def test_a_non_youtube_video_is_downloaded_directly(downloads):
    asset.download_asset(
        "https://example.com/trailer.mp4", "/assets/video.mp4", config.AssetType.VIDEO)

    assert [name for name, _ in downloads] == ["network"]


def test_the_url_and_target_reach_the_downloader(downloads):
    asset.download_asset(
        "https://example.com/art.jpg", "/assets/art.jpg", config.AssetType.BOXFRONT)
    kwargs = downloads[0][1]

    assert kwargs["url"] == "https://example.com/art.jpg"
    assert kwargs["output_file"] == "/assets/art.jpg"


def test_the_video_url_and_target_reach_the_video_downloader(downloads):
    asset.download_asset(
        "https://www.youtube.com/watch?v=abc123", "/assets/video.mp4",
        config.AssetType.VIDEO)
    kwargs = downloads[0][1]

    assert kwargs["video_url"] == "https://www.youtube.com/watch?v=abc123"
    assert kwargs["output_file"] == "/assets/video.mp4"


def test_a_failed_download_is_reported(monkeypatch):
    monkeypatch.setattr(asset.network, "download_url", lambda **kwargs: False)

    assert asset.download_asset(
        "https://example.com/art.jpg", "/assets/art.jpg",
        config.AssetType.BOXFRONT) is False


###########################################################
# Cleaning assets
###########################################################

def test_a_clean_asset_reports_success(installed, recording_command):
    assert asset.clean_asset("/assets/art.jpg", config.AssetType.BOXFRONT) is True


def test_a_failed_exif_clean_fails_the_asset(installed, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert asset.clean_asset("/assets/art.jpg", config.AssetType.BOXFRONT) is False


@pytest.mark.parametrize("asset_type", config.AssetType.members())
def test_every_asset_type_is_cleaned(installed, recording_command, asset_type):
    # Exif is not only an image concern; a scraped video carries it too.
    assert asset.clean_asset("/assets/file", asset_type) is True
    assert recording_command.ran() is True


###########################################################
# Converting
###########################################################

@pytest.fixture
def conversions(monkeypatch):
    calls = []
    monkeypatch.setattr(
        asset.image, "convert_image_to_jpeg",
        lambda **kwargs: calls.append(("convert", kwargs)) or True)
    monkeypatch.setattr(
        asset.fileops, "smart_transfer",
        lambda **kwargs: calls.append(("transfer", kwargs)) or True)
    return calls


@pytest.mark.parametrize("asset_type", config.AssetImageType.members())
def test_an_image_asset_is_converted_to_jpeg(conversions, asset_type):
    # The collection stores one image format so the front ends do not have to
    # guess.
    asset.convert_asset("/tmp/in.png", "/assets/out.jpg", asset_type)

    assert [name for name, _ in conversions] == ["convert", "transfer"]


def test_a_non_image_asset_is_only_transferred(conversions):
    non_image = [entry for entry in config.AssetType.members()
                 if entry not in config.AssetImageType.members()]
    if not non_image:
        pytest.skip("every asset type is an image")
    asset.convert_asset("/tmp/in.mp4", "/assets/out.mp4", non_image[0])

    assert [name for name, _ in conversions] == ["transfer"]


def test_a_failed_conversion_stops_the_transfer(monkeypatch):
    # Transferring an unconverted file would put the wrong format in the
    # collection under the right name.
    transfers = []
    monkeypatch.setattr(asset.image, "convert_image_to_jpeg", lambda **kwargs: False)
    monkeypatch.setattr(
        asset.fileops, "smart_transfer",
        lambda **kwargs: transfers.append(kwargs) or True)

    assert asset.convert_asset(
        "/tmp/in.png", "/assets/out.jpg", config.AssetImageType.members()[0]) is False
    assert transfers == []


def test_the_conversion_source_and_target_are_passed(conversions):
    asset.convert_asset(
        "/tmp/in.png", "/assets/out.jpg", config.AssetImageType.members()[0])
    kwargs = dict(conversions[0][1])

    assert kwargs["image_src"] == "/tmp/in.png"
    assert kwargs["image_dest"] == "/assets/out.jpg"


def test_an_existing_asset_is_not_overwritten_by_the_transfer(conversions):
    asset.convert_asset(
        "/tmp/in.png", "/assets/out.jpg", config.AssetImageType.members()[0])
    transfer = [kwargs for name, kwargs in conversions if name == "transfer"][0]

    assert transfer["skip_existing"] is True
