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


@pytest.mark.parametrize("api_base, local", [
    ("http://localhost:11434", True),
    ("http://127.0.0.1:11434", True),
    ("http://[::1]:11434", True),
    ("http://192.168.1.15:11434", False),
    ("http://llm:11434", False),
])
def test_only_a_server_on_this_machine_is_local(monkeypatch, api_base, local):
    monkeypatch.setattr(ollama, "get_api_base", lambda: api_base)

    assert ollama.is_local_server() is local


###########################################################
# Tunnel
#
# Through an SSH tunnel the base URL is on localhost, but the server is not
# this machine; starting a local ollama would quietly answer in its place.
###########################################################

@pytest.fixture
def tunneled(monkeypatch):
    values = {"ollama_ssh_host": "aryie@llm"}
    monkeypatch.setattr(
        ollama.settings, "get_value",
        lambda section, field, default_value = None, throw_exception = True: values.get(field, default_value))
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://localhost:11444")
    return values


def test_a_tunnel_end_on_localhost_is_not_a_local_server(tunneled):
    assert ollama.is_tunneled() is True
    assert ollama.is_local_server() is False


def test_no_ssh_host_means_no_tunnel(tunneled):
    tunneled["ollama_ssh_host"] = ""

    assert ollama.is_tunneled() is False
    assert ollama.is_local_server() is True


def test_a_tunnel_that_is_down_starts_nothing_locally(tunneled, monkeypatch, recording_command):
    monkeypatch.setattr(ollama, "is_running", lambda: False)

    assert ollama.start_serve() is False
    assert recording_command.ran() is False


###########################################################
# Updating the server
###########################################################

@pytest.fixture
def updating(tunneled, monkeypatch):
    state = {"versions": ["0.35.1", None, "0.36.0"], "slept": 0}
    monkeypatch.setattr(ollama, "get_server_version", lambda: state["versions"].pop(0) if state["versions"] else None)
    monkeypatch.setattr(ollama.runtime, "sleep_program", lambda seconds: state.update(slept = state["slept"] + 1))
    return state


def test_update_reruns_the_installer_on_the_server(updating, recording_command):
    assert ollama.action_update() is True
    assert recording_command.only() == ["ssh", "aryie@llm", ollama.OLLAMA_INSTALL_COMMAND]


def test_update_waits_for_the_server_to_answer_again(updating, recording_command):
    ollama.action_update()

    assert updating["versions"] == []
    assert updating["slept"] == 1


def test_update_needs_the_ssh_host(updating, recording_command, tunneled):
    tunneled["ollama_ssh_host"] = ""

    assert ollama.action_update() is False
    assert recording_command.ran() is False


def test_a_failed_installer_fails_the_update(updating, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert ollama.action_update() is False


def test_a_server_that_does_not_come_back_fails_the_update(updating, recording_command):
    updating["versions"] = ["0.35.1"]

    assert ollama.action_update() is False
    assert updating["slept"] == 30


def test_the_server_version_is_read_from_the_api(monkeypatch):
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://localhost:11444")
    monkeypatch.setattr(ollama.network, "get_remote_json",
        lambda url: {"version": "0.35.1"} if url == "http://localhost:11444/api/version" else None)

    assert ollama.get_server_version() == "0.35.1"


###########################################################
# Server hardware
#
# Fits are judged against the machine the models run on. A remote server
# cannot be measured from here, so its sizes come from the settings.
###########################################################

def settings_of(monkeypatch, values):
    monkeypatch.setattr(
        ollama.settings, "get_value",
        lambda section, field, default_value = None, throw_exception = True:
            values.get(field, default_value))


@pytest.mark.parametrize("value, expected", [("", None), ("  ", None), ("32768", 32768), (" 4096 ", 4096)])
def test_a_size_setting_is_read_in_megabytes(monkeypatch, value, expected):
    settings_of(monkeypatch, {"ollama_gpu_vram_mb": value})

    assert ollama.get_setting_mb("ollama_gpu_vram_mb") == expected


@pytest.mark.parametrize("value", ["32GB", "-1", "1.5"])
def test_a_size_setting_that_is_not_megabytes_is_ignored(monkeypatch, value):
    settings_of(monkeypatch, {"ollama_gpu_vram_mb": value})

    assert ollama.get_setting_mb("ollama_gpu_vram_mb") is None


@pytest.fixture
def machine(monkeypatch):
    state = {"warnings": []}
    monkeypatch.setattr(ollama.hardware, "get_hardware_summary", lambda: {
        "gpu_name": "Local card", "gpu_vram_total_mb": 4096, "gpu_vram_free_mb": 4000,
        "system_ram_mb": 16000, "system_ram_available_mb": 12000})
    monkeypatch.setattr(ollama.logger, "log_warning", lambda message: state["warnings"].append(message))
    monkeypatch.setattr(ollama, "read_helper_report", lambda: state.get("report"))
    return state


def test_a_local_server_is_this_machine(monkeypatch, machine):
    settings_of(monkeypatch, {"ollama_api_base": "http://localhost:11434"})

    hw = ollama.get_server_hardware()

    assert hw["gpu_vram_total_mb"] == 4096
    assert hw["system_ram_mb"] == 16000
    assert machine["warnings"] == []


def test_configured_sizes_replace_what_this_machine_has(monkeypatch, machine):
    settings_of(monkeypatch, {
        "ollama_api_base": "http://box:11434",
        "ollama_gpu_vram_mb": "32768",
        "ollama_system_ram_mb": "65536"})

    hw = ollama.get_server_hardware()

    assert hw["gpu_vram_total_mb"] == 32768
    assert hw["gpu_vram_free_mb"] == 32768
    assert hw["system_ram_mb"] == 65536
    assert "http://box:11434" in hw["gpu_name"]
    assert machine["warnings"] == []


def test_a_remote_server_without_sizes_warns_it_is_judged_locally(monkeypatch, machine):
    settings_of(monkeypatch, {"ollama_api_base": "http://box:11434"})

    hw = ollama.get_server_hardware()

    assert hw["gpu_vram_total_mb"] == 4096
    assert len(machine["warnings"]) == 1
    assert "ollama_gpu_vram_mb" in machine["warnings"][0]


REPORT = {
    "gpus": [
        {"name": "NVIDIA GeForce GTX 1650", "compute": False},
        {"name": "Tesla PG500-216", "compute": True},
        {"name": "Tesla V100", "compute": True}],
    "compute_vram_total_mb": 65536,
    "compute_vram_free_mb": 60000,
    "ram_total_mb": 30986,
    "ram_available_mb": 29877,
}


def test_the_helper_report_describes_a_remote_server(monkeypatch, machine):
    settings_of(monkeypatch, {"ollama_api_base": "http://box:11434"})
    machine["report"] = REPORT

    hw = ollama.get_server_hardware()

    assert hw["gpu_name"] == "Tesla PG500-216, Tesla V100"
    assert hw["gpu_vram_total_mb"] == 65536
    assert hw["gpu_vram_free_mb"] == 60000
    assert hw["system_ram_mb"] == 30986
    assert hw["system_ram_available_mb"] == 29877
    assert machine["warnings"] == []


def test_configured_sizes_win_over_the_helper_report(monkeypatch, machine):
    settings_of(monkeypatch, {"ollama_api_base": "http://box:11434", "ollama_gpu_vram_mb": "8192"})
    machine["report"] = REPORT

    hw = ollama.get_server_hardware()

    assert hw["gpu_vram_total_mb"] == 8192
    assert hw["system_ram_mb"] == 30986


@pytest.fixture
def helper_request(monkeypatch):
    state = {"urls": [], "reply": REPORT}
    monkeypatch.setattr(
        ollama.network, "get_remote_json", lambda url: state["urls"].append(url) or state["reply"])
    return state


@pytest.mark.parametrize("api_base, url", [
    ("http://192.168.1.15:11434", "http://192.168.1.15:11435/hardware"),
    ("http://llm:11434/", "http://llm:11435/hardware"),
    ("http://[fd00::15]:11434", "http://[fd00::15]:11435/hardware"),
])
def test_the_helper_is_asked_on_the_server_host(monkeypatch, helper_request, api_base, url):
    monkeypatch.setattr(ollama, "get_api_base", lambda: api_base)

    assert ollama.read_helper_report() == REPORT
    assert helper_request["urls"] == [url]


@pytest.mark.parametrize("reply", [None, [], {"gpus": []}])
def test_a_server_without_a_helper_has_no_report(monkeypatch, helper_request, reply):
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://box:11434")
    helper_request["reply"] = reply

    assert ollama.read_helper_report() is None


def test_an_api_base_without_a_host_has_no_report(monkeypatch, helper_request):
    monkeypatch.setattr(ollama, "get_api_base", lambda: "not a url")

    assert ollama.read_helper_report() is None
    assert helper_request["urls"] == []


def test_the_listing_prints_the_server_hardware(monkeypatch):
    printed = []
    monkeypatch.setattr(ollama, "get_server_hardware", lambda: {
        "gpu_vram_total_mb": 32768, "system_ram_mb": 65536})
    monkeypatch.setattr(ollama.hardware, "print_hardware_summary", lambda hw = None: printed.append(hw))
    monkeypatch.setattr(ollama, "get_recommended_models", lambda **kwargs: [])

    ollama.action_available(purpose = ollama.PURPOSE_CHAT)

    assert printed == [{"gpu_vram_total_mb": 32768, "system_ram_mb": 65536}]


@pytest.fixture
def server(monkeypatch):
    state = {"probes": [], "sleeps": 0}
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://localhost:11434")
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


def test_a_remote_server_that_is_not_answering_is_not_started(monkeypatch, server):
    server["probes"] = [False]
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://box:11434")

    assert ollama.start_serve() is False
    assert server["command"].ran() is False


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


@pytest.mark.parametrize("action", [
    lambda: ollama.pull_model("qwen3:8b"),
    lambda: ollama.delete_model("qwen3:8b"),
    lambda: ollama.show_model("qwen3:8b"),
])
def test_model_commands_act_on_the_configured_server(monkeypatch, action):
    # The ollama command ignores the setting and reads OLLAMA_HOST
    recorder = RecordingCommand(monkeypatch, output = "details")
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://box:11434")

    action()

    assert recorder.options().get_env_var("OLLAMA_HOST") == "http://box:11434"


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
