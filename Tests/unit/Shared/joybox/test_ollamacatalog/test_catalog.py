# Third-party imports
import pytest

# Local imports
from joybox import ollama
from joybox import ollamacatalog


###########################################################
# Remote catalog
###########################################################

SEARCH_PAGE = (
    '<a href="/library/qwen3" class="group">'
    '<p class="max-w-lg">A model</p>'
    '<span x-test-size class="tag">8b</span>')


@pytest.fixture
def search(monkeypatch):
    state = {"html": SEARCH_PAGE, "requests": []}

    def get_remote_html(url, headers = None):
        state["requests"].append((url, headers))
        return state["html"]
    monkeypatch.setattr(ollama.network, "get_remote_html", get_remote_html)
    monkeypatch.setattr(ollamacatalog, "remote_catalog_cache", {})
    return state


def test_an_unfiltered_search_infers_purposes(search):
    models = ollamacatalog.fetch_remote_models()

    assert search["requests"] == [("https://ollama.com/search", {"HX-Request": "true"})]
    assert models[0]["name"] == "qwen3:8b"
    assert models[0]["purpose"] == ollamacatalog.PURPOSE_CHAT


def test_a_purpose_filters_the_search_server_side(search):
    models = ollamacatalog.fetch_remote_models(ollamacatalog.PURPOSE_CLOUD)

    assert search["requests"][0][0] == \
        "https://ollama.com/search?c=%s" % ollamacatalog.PURPOSE_TO_SEARCH[ollamacatalog.PURPOSE_CLOUD]
    assert models[0]["purpose"] == ollamacatalog.PURPOSE_CLOUD


def test_a_purpose_without_a_search_filter_searches_everything(search):
    models = ollamacatalog.fetch_remote_models(ollamacatalog.PURPOSE_CHAT)

    assert search["requests"][0][0] == "https://ollama.com/search"
    assert models[0]["purpose"] == ollamacatalog.PURPOSE_CHAT


def test_an_unreachable_search_finds_nothing(search):
    search["html"] = None

    assert ollamacatalog.fetch_remote_models() == []


def test_a_link_without_a_name_is_skipped():
    assert ollamacatalog.parse_search_html('<a href="/library/"x">') == []


def test_the_remote_catalog_is_cached_per_purpose(search):
    first = ollamacatalog.get_model_catalog(ollamacatalog.PURPOSE_CHAT)
    second = ollamacatalog.get_model_catalog(ollamacatalog.PURPOSE_CHAT)

    assert first is second
    assert len(search["requests"]) == 1


def test_the_built_in_catalog_is_used_offline(search):
    search["html"] = None

    assert ollamacatalog.get_model_catalog() is ollamacatalog.FALLBACK_CATALOG
    assert ollamacatalog.remote_catalog_cache == {}


def test_the_built_in_catalog_is_filtered_by_purpose(search):
    search["html"] = None

    models = ollamacatalog.get_model_catalog(ollamacatalog.PURPOSE_TOOLS)

    assert models
    assert all(m["purpose"] == ollamacatalog.PURPOSE_TOOLS for m in models)


###########################################################
# Tags
###########################################################

def tag_link(family, tag, size, context):
    return (
        '<a href="/library/%s:%s" class="md:hidden flex">'
        '<span>%s</span> · <span>%s context window</span></a>' % (family, tag, size, context))


@pytest.fixture
def tags_page(monkeypatch):
    state = {"html": "", "requests": []}

    def get_remote_html(url, headers = None):
        state["requests"].append(url)
        return state["html"]
    monkeypatch.setattr(ollama.network, "get_remote_html", get_remote_html)
    return state


def test_tags_are_read_for_the_model_family(tags_page):
    tags_page["html"] = tag_link("qwen3", "8b", "5.2GB", "40K") + \
        tag_link("qwen3", "8b-q8_0", "8.9GB", "40K")

    tags = ollamacatalog.get_model_tags("qwen3:8b")

    assert tags_page["requests"] == ["https://ollama.com/library/qwen3/tags"]
    assert tags[0] == {
        "tag": "8b",
        "full_name": "qwen3:8b",
        "size_str": "5.2GB",
        "size_mb": 4959,
        "context": "40K",
    }
    assert tags[1]["full_name"] == "qwen3:8b-q8_0"


def test_a_repeated_tag_is_listed_once(tags_page):
    tags_page["html"] = tag_link("qwen3", "8b", "5.2GB", "40K") * 2

    assert len(ollamacatalog.get_model_tags("qwen3")) == 1


def test_an_unreachable_tags_page_has_no_tags(tags_page):
    tags_page["html"] = None

    assert ollamacatalog.get_model_tags("qwen3") == []


###########################################################
# Quantization options
###########################################################

def tags_of(monkeypatch, tags):
    monkeypatch.setattr(ollamacatalog, "get_model_tags", lambda base_name: tags)


def tag(name, size_mb = 4700):
    return {
        "tag": name,
        "full_name": "qwen3:%s" % name,
        "size_str": "4.7GB",
        "size_mb": size_mb,
        "context": "128K",
    }


def test_only_the_asked_for_size_is_offered(monkeypatch):
    # Offering a 14b build for an 8b request downloads twice what was chosen.
    tags_of(monkeypatch, [tag("8b"), tag("8b-q8_0"), tag("14b"), tag("14b-q8_0")])

    options = ollamacatalog.get_quantization_options("qwen3:8b")

    assert [option["tag"] for option in options] == ["8b", "8b-q8_0"]


def test_an_unsuffixed_tag_is_the_default_quantization(monkeypatch):
    tags_of(monkeypatch, [tag("8b")])

    assert ollamacatalog.get_quantization_options("qwen3:8b")[0]["quantization"] == "default"


def test_a_suffixed_tag_keeps_its_quantization_name(monkeypatch):
    tags_of(monkeypatch, [tag("8b-q4_K_M")])

    assert ollamacatalog.get_quantization_options("qwen3:8b")[0]["quantization"] == "q4_K_M"


def test_a_model_named_without_a_size_has_no_options(monkeypatch):
    tags_of(monkeypatch, [tag("8b")])

    assert ollamacatalog.get_quantization_options("qwen3") == []


def test_a_size_that_only_prefixes_another_is_not_matched(monkeypatch):
    # "8b" must not pull in "8b-instruct"'s neighbour "80b".
    tags_of(monkeypatch, [tag("8b"), tag("80b")])

    assert [option["tag"] for option in ollamacatalog.get_quantization_options("qwen3:8b")] == ["8b"]
