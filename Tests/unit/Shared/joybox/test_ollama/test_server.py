# Third-party imports
import pytest

# Local imports
from joybox import ollama
from fakes import RecordingCommand


###########################################################
# Server
#
# The local server is probed over HTTP and started as a daemon when it is not
# answering. Both the probe and the process are faked.
###########################################################

def test_the_api_base_defaults_to_the_local_server(monkeypatch):
    monkeypatch.setattr(
        ollama.settings, "get_value",
        lambda section, field, default_value = None, throw_exception = True: default_value)

    assert ollama.get_api_base() == ollama.OLLAMA_API_BASE_DEFAULT


def test_the_server_is_probed_at_the_configured_base(monkeypatch):
    probed = []
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://box:1234")
    monkeypatch.setattr(
        ollama.network, "is_url_reachable", lambda url: probed.append(url) or True)

    assert ollama.is_running() is True
    assert probed == ["http://box:1234"]


@pytest.fixture
def server(monkeypatch):
    state = {"probes": [], "sleeps": 0}
    monkeypatch.setattr(ollama, "is_running", lambda: state["probes"].pop(0))
    monkeypatch.setattr(
        ollama.runtime, "sleep_program",
        lambda seconds: state.__setitem__("sleeps", state["sleeps"] + 1))
    state["command"] = RecordingCommand(monkeypatch)
    return state


def test_a_running_server_is_not_started_again(server):
    server["probes"] = [True]

    assert ollama.start_serve() is True
    assert server["command"].ran() is False


def test_a_stopped_server_is_started_as_a_daemon(server):
    server["probes"] = [False, False, True]

    assert ollama.start_serve() is True
    assert server["command"].only() == ["ollama", "serve"]
    assert server["command"].options().is_daemon() is True
    assert server["sleeps"] == 2


def test_a_server_that_never_answers_fails_to_start(server):
    server["probes"] = [False] * 11

    assert ollama.start_serve() is False
    assert server["sleeps"] == 10


def test_ensure_running_leaves_a_running_server_alone(monkeypatch, server):
    server["probes"] = [True]
    monkeypatch.setattr(ollama, "start_serve", lambda: pytest.fail("started"))

    assert ollama.ensure_running() is True


def test_ensure_running_starts_a_stopped_server(monkeypatch, server):
    server["probes"] = [False]
    monkeypatch.setattr(ollama, "start_serve", lambda: True)

    assert ollama.ensure_running() is True


###########################################################
# Installed models
###########################################################

def test_installed_models_are_read_from_the_tags_endpoint(monkeypatch):
    requested = []
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://box")

    def get_remote_json(url):
        requested.append(url)
        return {"models": [
            {"name": "zeta:1b", "size": 2 * 1024 ** 3, "details": {
                "family": "zeta", "parameter_size": "1B",
                "quantization_level": "Q4_0", "format": "gguf"}},
            {"name": "alpha:7b"},
        ]}
    monkeypatch.setattr(ollama.network, "get_remote_json", get_remote_json)

    models = ollama.list_installed_models()

    assert requested == ["http://box/api/tags"]
    assert [m["name"] for m in models] == ["alpha:7b", "zeta:1b"]
    assert models[0]["size_gb"] == 0
    assert models[0]["family"] == ""
    assert models[1]["size_gb"] == 2.0
    assert models[1]["quantization"] == "Q4_0"
    assert models[1]["format"] == "gguf"


@pytest.mark.parametrize("reply", [None, {}, {"error": "x"}])
def test_an_unusable_tags_reply_lists_nothing(monkeypatch, reply):
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://box")
    monkeypatch.setattr(ollama.network, "get_remote_json", lambda url: reply)

    assert ollama.list_installed_models() == []


###########################################################
# Model commands
###########################################################

def test_a_pull_streams_its_progress(monkeypatch):
    recorder = RecordingCommand(monkeypatch)

    assert ollama.pull_model("qwen3:8b") is True
    assert recorder.only() == ["ollama", "pull", "qwen3:8b"]
    assert recorder.options().is_passthrough() is True


def test_a_failed_pull_reports_failure(monkeypatch):
    RecordingCommand(monkeypatch, returncode = 1)

    assert ollama.pull_model("qwen3:8b") is False


@pytest.mark.parametrize("returncode, expected", [(0, True), (1, False)])
def test_a_delete_reports_its_outcome(monkeypatch, returncode, expected):
    recorder = RecordingCommand(monkeypatch, returncode = returncode)

    assert ollama.delete_model("qwen3:8b") is expected
    assert recorder.only() == ["ollama", "rm", "qwen3:8b"]


def test_model_information_is_the_command_output(monkeypatch):
    recorder = RecordingCommand(monkeypatch, output = "details")

    assert ollama.show_model("qwen3:8b") == "details"
    assert recorder.only() == ["ollama", "show", "qwen3:8b"]


def test_no_output_is_no_information(monkeypatch):
    RecordingCommand(monkeypatch, output = "")

    assert ollama.show_model("qwen3:8b") is None


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
    monkeypatch.setattr(ollama, "remote_catalog_cache", {})
    return state


def test_an_unfiltered_search_infers_purposes(search):
    models = ollama.fetch_remote_models()

    assert search["requests"] == [("https://ollama.com/search", {"HX-Request": "true"})]
    assert models[0]["name"] == "qwen3:8b"
    assert models[0]["purpose"] == ollama.PURPOSE_CHAT


def test_a_purpose_filters_the_search_server_side(search):
    models = ollama.fetch_remote_models(ollama.PURPOSE_CLOUD)

    assert search["requests"][0][0] == \
        "https://ollama.com/search?c=%s" % ollama.PURPOSE_TO_SEARCH[ollama.PURPOSE_CLOUD]
    assert models[0]["purpose"] == ollama.PURPOSE_CLOUD


def test_a_purpose_without_a_search_filter_searches_everything(search):
    models = ollama.fetch_remote_models(ollama.PURPOSE_CHAT)

    assert search["requests"][0][0] == "https://ollama.com/search"
    assert models[0]["purpose"] == ollama.PURPOSE_CHAT


def test_an_unreachable_search_finds_nothing(search):
    search["html"] = None

    assert ollama.fetch_remote_models() == []


def test_a_link_without_a_name_is_skipped():
    assert ollama.parse_search_html('<a href="/library/"x">') == []


def test_the_remote_catalog_is_cached_per_purpose(search):
    first = ollama.get_model_catalog(ollama.PURPOSE_CHAT)
    second = ollama.get_model_catalog(ollama.PURPOSE_CHAT)

    assert first is second
    assert len(search["requests"]) == 1


def test_the_built_in_catalog_is_used_offline(search):
    search["html"] = None

    assert ollama.get_model_catalog() is ollama.FALLBACK_CATALOG
    assert ollama.remote_catalog_cache == {}


def test_the_built_in_catalog_is_filtered_by_purpose(search):
    search["html"] = None

    models = ollama.get_model_catalog(ollama.PURPOSE_TOOLS)

    assert models
    assert all(m["purpose"] == ollama.PURPOSE_TOOLS for m in models)


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

    tags = ollama.get_model_tags("qwen3:8b")

    assert tags_page["requests"] == ["https://ollama.com/library/qwen3/tags"]
    assert tags[0] == {
        "tag": "8b",
        "full_name": "qwen3:8b",
        "size_str": "5.2GB",
        "size_mb": 5324,
        "context": "40K",
    }
    assert tags[1]["full_name"] == "qwen3:8b-q8_0"


def test_a_repeated_tag_is_listed_once(tags_page):
    tags_page["html"] = tag_link("qwen3", "8b", "5.2GB", "40K") * 2

    assert len(ollama.get_model_tags("qwen3")) == 1


def test_an_unreachable_tags_page_has_no_tags(tags_page):
    tags_page["html"] = None

    assert ollama.get_model_tags("qwen3") == []


###########################################################
# Pulling with a quantization choice
###########################################################

@pytest.fixture
def puller(monkeypatch):
    state = {"options": [], "selection": None, "pulled": [], "result": True, "shown": []}
    monkeypatch.setattr(ollama.hardware, "get_hardware_summary", lambda: {
        "gpu_vram_total_mb": 8000, "system_ram_mb": 32000})
    monkeypatch.setattr(ollama, "get_quantization_options", lambda name: state["options"])
    monkeypatch.setattr(
        ollama, "pull_model", lambda name: state["pulled"].append(name) or state["result"])

    def prompt_for_selection(message, options, display_func = None):
        state["shown"] = [display_func(o) for o in options]
        return None if state["selection"] is None else options[state["selection"]]
    monkeypatch.setattr(ollama.prompts, "prompt_for_selection", prompt_for_selection)
    return state


def quant(full_name, size_mb):
    return {"full_name": full_name, "size_mb": size_mb, "size_str": "?", "context": "40K"}


def test_a_model_with_one_quantization_is_pulled_as_named(puller):
    puller["options"] = [quant("qwen3:8b", 5000)]

    assert ollama.pull_with_quantization("qwen3:8b") is True
    assert puller["pulled"] == ["qwen3:8b"]


def test_the_chosen_quantization_is_pulled(puller):
    puller["options"] = [quant("qwen3:8b", 5000), quant("qwen3:8b-fp16", 16000)]
    puller["selection"] = 1

    assert ollama.pull_with_quantization("qwen3:8b") is True
    assert puller["pulled"] == ["qwen3:8b-fp16"]
    assert puller["shown"][0].startswith("[+]")
    assert puller["shown"][1].startswith("[~]")


def test_declining_the_quantization_pulls_nothing(puller):
    puller["options"] = [quant("qwen3:8b", 5000), quant("qwen3:8b-fp16", 16000)]

    assert ollama.pull_with_quantization("qwen3:8b") is True
    assert puller["pulled"] == []


def test_a_failed_pull_is_reported(puller):
    puller["result"] = False

    assert ollama.pull_with_quantization("qwen3:8b") is False
