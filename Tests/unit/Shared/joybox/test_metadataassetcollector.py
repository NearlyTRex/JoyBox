# Third-party imports
import pytest

# Local imports
import joybox.config as config
import joybox.metadataassetcollector as metadataassetcollector


class FakeResult:
    def __init__(self, url):
        self.url = url

    def get_description(self):
        return "result " + self.url

    def get_url(self):
        return self.url


@pytest.fixture
def sources(monkeypatch):
    calls = []

    def recorder(source, results):
        def find(**kwargs):
            calls.append((source, kwargs))
            return [FakeResult(url) for url in results]
        return find

    monkeypatch.setattr(metadataassetcollector.google, "find_images", recorder("images", ["https://img/1"]))
    monkeypatch.setattr(metadataassetcollector.google, "find_videos", recorder("videos", ["https://vid/1"]))
    monkeypatch.setattr(metadataassetcollector.stores, "find_steam_assets", recorder("steam", ["https://steam/1"]))
    monkeypatch.setattr(metadataassetcollector.stores, "find_steam_griddb_covers", recorder("griddb", ["https://grid/1"]))
    monkeypatch.setattr(metadataassetcollector.logger, "log_info", lambda message, **kwargs: None)
    return calls


def answer(monkeypatch, value):
    monkeypatch.setattr(metadataassetcollector.prompts, "prompt_for_value", lambda prompt: value)


###########################################################
# Source filters
###########################################################

def test_boxfront_searches_images_steam_and_griddb(sources):
    results = metadataassetcollector.find_metadata_assets_from_google_images("PC", "Doom (USA)", config.AssetType.BOXFRONT)
    results += metadataassetcollector.find_metadata_assets_from_youtube("PC", "Doom (USA)", config.AssetType.BOXFRONT)
    results += metadataassetcollector.find_metadata_assets_from_steam("PC", "Doom (USA)", config.AssetType.BOXFRONT)
    results += metadataassetcollector.find_metadata_assets_from_steamgriddb("PC", "Doom (USA)", config.AssetType.BOXFRONT)

    assert [url.get_url() for url in results] == ["https://img/1", "https://steam/1", "https://grid/1"]
    assert [source for source, kwargs in sources] == ["images", "steam", "griddb"]
    assert all(kwargs["search_name"] == "Doom" for source, kwargs in sources)


def test_video_searches_youtube_trailers_and_steam(sources):
    results = metadataassetcollector.find_metadata_assets_from_google_images("PC", "Doom", config.AssetType.VIDEO)
    results += metadataassetcollector.find_metadata_assets_from_youtube("PC", "Doom", config.AssetType.VIDEO)
    results += metadataassetcollector.find_metadata_assets_from_steam("PC", "Doom", config.AssetType.VIDEO)
    results += metadataassetcollector.find_metadata_assets_from_steamgriddb("PC", "Doom", config.AssetType.VIDEO)

    assert [url.get_url() for url in results] == ["https://vid/1", "https://steam/1"]
    assert sources[0][1]["search_name"] == "Doom trailer"


def test_other_asset_types_search_nothing(sources):
    assert metadataassetcollector.find_metadata_assets_from_steam("PC", "Doom", config.AssetType.LABEL) == []
    assert sources == []


###########################################################
# Manual selection
###########################################################

def test_an_index_selects_that_result(monkeypatch, sources):
    answer(monkeypatch, "2")

    assert metadataassetcollector.find_metadata_asset("PC", "Doom", config.AssetType.BOXFRONT) == "https://grid/1"


def test_a_pasted_url_is_used_directly(monkeypatch, sources):
    answer(monkeypatch, "https://custom/cover.jpg")

    assert metadataassetcollector.find_metadata_asset("PC", "Doom", config.AssetType.BOXFRONT) == "https://custom/cover.jpg"


@pytest.mark.parametrize("value", ["", "9", "cover"])
def test_a_blank_or_unusable_answer_selects_nothing(monkeypatch, sources, value):
    answer(monkeypatch, value)

    assert metadataassetcollector.find_metadata_asset("PC", "Doom", config.AssetType.BOXFRONT) is None
