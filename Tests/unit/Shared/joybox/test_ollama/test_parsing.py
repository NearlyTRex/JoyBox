# Third-party imports
import pytest

# Local imports
from joybox import ollama



###########################################################
# Size and context parsing
#
# Every figure comes off ollama.com as a compact string. These decide whether
# a model is offered at all, so a misread suffix either hides a model that
# would run or recommends one that cannot load.
###########################################################

@pytest.mark.parametrize("value,expected", [
    ("7b", 7 * ollama.VRAM_MB_PER_BILLION_PARAMS),
    ("0.5b", int(0.5 * ollama.VRAM_MB_PER_BILLION_PARAMS)),
    ("120b", 120 * ollama.VRAM_MB_PER_BILLION_PARAMS),
])
def test_a_parameter_count_becomes_a_vram_estimate(value, expected):
    assert ollama.estimate_vram_mb(value) == expected


def test_millions_of_parameters_are_scaled_down():
    # A 137M model needs a fraction of a gigabyte, not 137 times a billion.
    assert ollama.estimate_vram_mb("137m") == \
        int(137 / 1000 * ollama.VRAM_MB_PER_BILLION_PARAMS)


def test_a_large_bare_number_is_read_as_millions():
    # Ollama writes some sizes without a suffix, and nothing has 700 billion
    # parameters sitting in the same list as 7.
    assert ollama.estimate_vram_mb("700") == ollama.estimate_vram_mb("700m")


def test_a_small_bare_number_is_read_as_billions():
    assert ollama.estimate_vram_mb("7") == ollama.estimate_vram_mb("7b")


def test_an_uppercase_size_is_accepted():
    assert ollama.estimate_vram_mb("7B") == ollama.estimate_vram_mb("7b")


@pytest.mark.parametrize("value", ["?", "", "large", "7gb", "7 b"])
def test_an_unparseable_size_estimates_nothing(value):
    assert ollama.estimate_vram_mb(value) == 0


@pytest.mark.parametrize("value,expected", [
    ("14B", 14.0),
    ("0.5b", 0.5),
    ("400M", 0.4),
    ("7", 7.0),
])
def test_a_parameter_count_is_parsed_for_ranking(value, expected):
    assert ollama.parse_param_count(value) == pytest.approx(expected)


@pytest.mark.parametrize("value", ["?", "", None, "unknown"])
def test_an_unparseable_parameter_count_ranks_lowest(value):
    assert ollama.parse_param_count(value) == 0.0


@pytest.mark.parametrize("value,expected", [
    ("128K", 128 * 1024),
    ("8192", 8192),
    ("1M", 1024 * 1024),
    ("4k", 4096),
])
def test_a_context_window_is_parsed_into_tokens(value, expected):
    assert ollama.parse_context_tokens(value) == expected


@pytest.mark.parametrize("value", ["", "?", "unknown", None])
def test_an_unparseable_context_window_is_nothing(value):
    assert ollama.parse_context_tokens(value) == 0


@pytest.mark.parametrize("value,expected", [
    ("5.2GB", int(5.2 * 1024)),
    ("890MB", 890),
    ("1TB", 1024 * 1024),
    ("512KB", 1),
])
def test_a_download_size_is_parsed_into_megabytes(value, expected):
    assert ollama.parse_size_to_mb(value) == expected


def test_a_download_size_is_parsed_whatever_its_case():
    assert ollama.parse_size_to_mb("5.2gb") == ollama.parse_size_to_mb("5.2GB")


def test_a_download_size_may_carry_a_space():
    assert ollama.parse_size_to_mb("5.2 GB") == ollama.parse_size_to_mb("5.2GB")


@pytest.mark.parametrize("value", ["", "?", "5.2", "GB", "big"])
def test_an_unparseable_download_size_is_nothing(value):
    assert ollama.parse_size_to_mb(value) == 0


###########################################################
# Search results
###########################################################

def library_block(name, description = "", capabilities = (), sizes = (), pulls = ""):
    # One entry as ollama.com's search endpoint renders it.
    block = '<a href="/library/%s" class="group">' % name
    block += '<p class="max-w-lg break-words">%s</p>' % description
    for capability in capabilities:
        block += '<span x-test-capability class="tag">%s</span>' % capability
    for size in sizes:
        block += '<span x-test-size class="tag">%s</span>' % size
    if pulls:
        block += '<span x-test-pull-count>%s</span>' % pulls
    return block


def test_a_model_is_read_out_of_the_search_page():
    html = library_block("qwen3", description = "A model", sizes = ["8b"], pulls = "1.2M")

    models = ollama.parse_search_html(html)

    assert len(models) == 1
    assert models[0]["name"] == "qwen3:8b"
    assert models[0]["description"] == "A model"
    assert models[0]["pulls"] == "1.2M"


def test_each_size_becomes_its_own_entry():
    # The sizes of one model have different hardware requirements, so they are
    # offered separately rather than as one name.
    html = library_block("qwen3", sizes = ["8b", "14b", "32b"])

    models = ollama.parse_search_html(html)

    assert [model["name"] for model in models] == ["qwen3:8b", "qwen3:14b", "qwen3:32b"]


def test_a_size_entry_carries_its_own_estimate():
    html = library_block("qwen3", sizes = ["8b"])

    assert ollama.parse_search_html(html)[0]["vram_mb"] == ollama.estimate_vram_mb("8b")


@pytest.mark.parametrize("capability,purpose", [
    ("tools", ollama.PURPOSE_TOOLS),
    ("thinking", ollama.PURPOSE_REASONING),
    ("vision", ollama.PURPOSE_VISION),
    ("embedding", ollama.PURPOSE_EMBEDDING),
])
def test_a_capability_decides_the_purpose(capability, purpose):
    html = library_block("model", capabilities = [capability], sizes = ["8b"])

    assert ollama.parse_search_html(html)[0]["purpose"] == purpose


def test_a_model_without_capabilities_is_a_chat_model():
    html = library_block("model", sizes = ["8b"])

    assert ollama.parse_search_html(html)[0]["purpose"] == ollama.PURPOSE_CHAT


def test_an_unknown_capability_does_not_change_the_purpose():
    html = library_block("model", capabilities = ["something-new"], sizes = ["8b"])

    assert ollama.parse_search_html(html)[0]["purpose"] == ollama.PURPOSE_CHAT


def test_a_filtered_search_keeps_the_purpose_it_asked_for():
    # A cloud search returns models whose own tags say "tools"; the filter is
    # what makes them cloud models.
    html = library_block("model", capabilities = ["tools"], sizes = ["8b"])

    models = ollama.parse_search_html(html, filter_purpose = ollama.PURPOSE_CLOUD)

    assert models[0]["purpose"] == ollama.PURPOSE_CLOUD


def test_a_model_with_no_sizes_is_cloud_only():
    # Nothing to download means nothing to run locally, which is a different
    # thing from a model that is too big for the machine.
    html = library_block("big-model", description = "Hosted")

    models = ollama.parse_search_html(html)

    assert models[0]["cloud_only"] is True
    assert models[0]["params"] == "?"


def test_html_entities_in_a_description_are_decoded():
    html = library_block("model", description = "Meta&#39;s model &amp; friends", sizes = ["8b"])

    assert ollama.parse_search_html(html)[0]["description"] == "Meta's model & friends"


def test_a_page_with_no_models_parses_to_nothing():
    assert ollama.parse_search_html("<html><body>nothing here</body></html>") == []


def test_every_model_on_the_page_is_read():
    html = library_block("first", sizes = ["8b"]) + library_block("second", sizes = ["8b"])

    assert [model["name"] for model in ollama.parse_search_html(html)] == \
        ["first:8b", "second:8b"]
