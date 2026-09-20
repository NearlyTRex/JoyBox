# Imports
import pytest

# Local imports
from joybox import ollama


###########################################################
# Action dispatch
#
# Every action takes the same keyword signature so the CLI can dispatch without
# knowing which options each one reads.
###########################################################

def test_the_documented_actions_exist():
    # These names are the tool's positional argument.
    for action in ["list", "available", "best", "pull", "delete", "info", "harness"]:
        assert action in ollama.get_action_keys()


def test_every_action_is_callable():
    for action, handler in ollama.ACTIONS.items():
        assert callable(handler), f"{action} is not callable"


def test_every_action_accepts_the_shared_signature():
    # Dispatch passes all four keywords, so a missing one raises at call time.
    import inspect
    for action, handler in ollama.ACTIONS.items():
        parameters = inspect.signature(handler).parameters
        for keyword in ["model_name", "purpose", "harness", "show_all"]:
            assert keyword in parameters, f"{action} does not accept {keyword}"


def test_an_unknown_action_fails_rather_than_raising():
    assert ollama.run_action("nonsense") is False


def test_dispatch_forwards_every_option(monkeypatch):
    received = {}

    def fake_action(model_name = None, purpose = None, harness = None, show_all = False):
        received.update({
            "model_name": model_name,
            "purpose": purpose,
            "harness": harness,
            "show_all": show_all,
        })
        return True

    monkeypatch.setitem(ollama.ACTIONS, "list", fake_action)

    assert ollama.run_action(
        "list",
        model_name = "llama3",
        purpose = "tools",
        harness = "codex",
        show_all = True) is True

    assert received == {
        "model_name": "llama3",
        "purpose": "tools",
        "harness": "codex",
        "show_all": True,
    }


def test_dispatch_returns_what_the_action_returns(monkeypatch):
    monkeypatch.setitem(ollama.ACTIONS, "list", lambda **kwargs: False)
    assert ollama.run_action("list") is False


###########################################################
# Harnesses
###########################################################

def test_the_default_harness_is_a_known_one():
    assert ollama.DEFAULT_HARNESS in ollama.HARNESSES


def test_every_harness_has_a_display_name():
    for key, harness in ollama.HARNESSES.items():
        assert harness.get("name"), f"harness {key} has no name"


def test_harness_keys_match_the_harness_table():
    assert sorted(ollama.get_harness_keys()) == sorted(ollama.HARNESSES.keys())


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


###########################################################
# Hardware fit
###########################################################

def catalog_of(monkeypatch, models):
    monkeypatch.setattr(ollama, "get_model_catalog", lambda purpose = None: models)


def model(name = "model:8b", purpose = None, vram_mb = 5000, **extra):
    entry = {
        "name": name,
        "display": name,
        "purpose": purpose or ollama.PURPOSE_CHAT,
        "params": "8B",
        "vram_mb": vram_mb,
        "description": "A model",
    }
    entry.update(extra)
    return entry


def test_a_model_that_fits_vram_runs_on_the_gpu(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 4000)])

    found = ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000)

    assert found[0]["fit"] == ollama.FIT_GPU
    assert found[0]["fits_vram"] is True


def test_a_model_larger_than_vram_offloads_to_ram(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 12000)])

    found = ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000)

    assert found[0]["fit"] == ollama.FIT_OFFLOAD
    assert found[0]["fits_vram"] is False


def test_a_model_larger_than_the_machine_is_left_out(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 64000)])

    assert ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000) == []


def test_an_oversized_model_can_be_asked_for(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 64000)])

    found = ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000, include_unfit = True)

    assert found[0]["fit"] == ollama.FIT_NONE


def test_a_cloud_model_is_left_out_of_local_recommendations(monkeypatch):
    catalog_of(monkeypatch, [model(cloud_only = True, vram_mb = 0)])

    assert ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000) == []


def test_asking_for_cloud_models_includes_them(monkeypatch):
    catalog_of(monkeypatch, [model(purpose = ollama.PURPOSE_CLOUD, cloud_only = True, vram_mb = 0)])

    found = ollama.get_recommended_models(
        purpose = ollama.PURPOSE_CLOUD, vram_mb = 8000, ram_mb = 32000)

    assert found[0]["fit"] == ollama.FIT_CLOUD


def test_a_model_of_unknown_size_does_not_fit(monkeypatch):
    # An unknown size cannot be promised to load, so it is not recommended.
    catalog_of(monkeypatch, [model(vram_mb = 0)])

    assert ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000) == []


def test_recommendations_are_ordered_by_how_well_they_run(monkeypatch):
    catalog_of(monkeypatch, [
        model(name = "offload:14b", vram_mb = 12000),
        model(name = "gpu:8b", vram_mb = 4000),
    ])

    found = ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000)

    assert [entry["name"] for entry in found] == ["gpu:8b", "offload:14b"]


def test_another_purpose_is_filtered_out(monkeypatch):
    catalog_of(monkeypatch, [
        model(name = "chat:8b", purpose = ollama.PURPOSE_CHAT),
        model(name = "tools:8b", purpose = ollama.PURPOSE_TOOLS),
    ])

    found = ollama.get_recommended_models(
        purpose = ollama.PURPOSE_TOOLS, vram_mb = 8000, ram_mb = 32000)

    assert [entry["name"] for entry in found] == ["tools:8b"]


def test_the_catalog_is_left_unmodified(monkeypatch):
    # The fit depends on the machine asking, so it cannot be written into a
    # catalog that is cached and reused.
    entry = model()
    catalog_of(monkeypatch, [entry])

    ollama.get_recommended_models(vram_mb = 8000, ram_mb = 32000)

    assert "fit" not in entry


###########################################################
# Picking a model
###########################################################

def test_the_largest_model_that_fits_the_gpu_wins(monkeypatch):
    catalog_of(monkeypatch, [
        model(name = "small:8b", vram_mb = 4000, params = "8B"),
        model(name = "large:14b", vram_mb = 7000, params = "14B"),
    ])

    best = ollama.get_best_model(purpose = None, vram_mb = 8000, ram_mb = 32000)

    assert best["name"] == "large:14b"


def test_a_gpu_model_beats_a_larger_offloaded_one(monkeypatch):
    # Offloading to system RAM is far slower than a smaller model on the GPU.
    catalog_of(monkeypatch, [
        model(name = "offload:32b", vram_mb = 20000, params = "32B"),
        model(name = "gpu:8b", vram_mb = 4000, params = "8B"),
    ])

    best = ollama.get_best_model(purpose = None, vram_mb = 8000, ram_mb = 32000)

    assert best["name"] == "gpu:8b"


def test_the_largest_offloaded_model_is_taken_when_nothing_fits_the_gpu(monkeypatch):
    catalog_of(monkeypatch, [
        model(name = "mid:14b", vram_mb = 12000, params = "14B"),
        model(name = "big:32b", vram_mb = 20000, params = "32B"),
    ])

    best = ollama.get_best_model(purpose = None, vram_mb = 2000, ram_mb = 32000)

    assert best["name"] == "big:32b"


def test_nothing_is_picked_when_nothing_runs(monkeypatch):
    catalog_of(monkeypatch, [model(vram_mb = 64000)])

    assert ollama.get_best_model(purpose = None, vram_mb = 4000, ram_mb = 8000) is None


###########################################################
# Display
###########################################################

def test_a_fitting_model_is_marked_as_such():
    line = ollama.format_model_display(model(vram_mb = 5000, fits_vram = True))

    assert line.startswith("[+]")


def test_a_model_that_does_not_fit_is_marked_differently():
    line = ollama.format_model_display(model(vram_mb = 64000, fits_vram = False))

    assert line.startswith("[-]")


def test_a_display_line_reports_the_size_in_gigabytes():
    line = ollama.format_model_display(model(vram_mb = 5120, fits_vram = True))

    assert "5.0 GB" in line


def test_an_installed_model_is_described_by_its_build():
    line = ollama.format_installed_model_display({
        "name": "qwen3:8b",
        "size_gb": 4.7,
        "parameter_size": "8B",
        "quantization": "Q4_K_M",
    })

    assert line == "qwen3:8b (4.7 GB, 8B Q4_K_M)"


@pytest.mark.parametrize("vram_mb,ram_mb,marker", [
    (8000, 32000, "+"),
    (2000, 32000, "~"),
    (2000, 3000, "-"),
])
def test_a_quantization_is_marked_by_where_it_would_run(vram_mb, ram_mb, marker):
    option = {
        "full_name": "qwen3:8b-q4_K_M",
        "size_mb": 4700,
        "size_str": "4.7GB",
        "context": "128K",
    }

    line = ollama.format_quantization_display(option, vram_mb, ram_mb)

    assert line.startswith("[%s]" % marker)
    assert "qwen3:8b-q4_K_M" in line
    assert "128K context" in line


###########################################################
# Quantization options
###########################################################

def tags_of(monkeypatch, tags):
    monkeypatch.setattr(ollama, "get_model_tags", lambda base_name: tags)


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

    options = ollama.get_quantization_options("qwen3:8b")

    assert [option["tag"] for option in options] == ["8b", "8b-q8_0"]


def test_an_unsuffixed_tag_is_the_default_quantization(monkeypatch):
    tags_of(monkeypatch, [tag("8b")])

    assert ollama.get_quantization_options("qwen3:8b")[0]["quantization"] == "default"


def test_a_suffixed_tag_keeps_its_quantization_name(monkeypatch):
    tags_of(monkeypatch, [tag("8b-q4_K_M")])

    assert ollama.get_quantization_options("qwen3:8b")[0]["quantization"] == "q4_K_M"


def test_a_model_named_without_a_size_has_no_options(monkeypatch):
    tags_of(monkeypatch, [tag("8b")])

    assert ollama.get_quantization_options("qwen3") == []


def test_a_size_that_only_prefixes_another_is_not_matched(monkeypatch):
    # "8b" must not pull in "8b-instruct"'s neighbour "80b".
    tags_of(monkeypatch, [tag("8b"), tag("80b")])

    assert [option["tag"] for option in ollama.get_quantization_options("qwen3:8b")] == ["8b"]


###########################################################
# Harness context requirements
###########################################################

def test_a_model_meeting_the_minimum_is_accepted(monkeypatch):
    monkeypatch.setattr(
        ollama, "get_quantization_options",
        lambda model_name: [{"context": "128K"}])

    assert ollama.check_context_window("qwen3:8b", "claude_code") is True


def test_a_model_below_the_minimum_is_refused(monkeypatch):
    # A short context silently truncates an agent's conversation rather than
    # failing, so it is caught before the harness starts.
    monkeypatch.setattr(
        ollama, "get_quantization_options",
        lambda model_name: [{"context": "4K"}])

    assert ollama.check_context_window("qwen3:8b", "claude_code") is False


def test_a_requirement_can_be_given_directly(monkeypatch):
    monkeypatch.setattr(
        ollama, "get_quantization_options",
        lambda model_name: [{"context": "8K"}])

    assert ollama.check_context_window("qwen3:8b", {"name": "Custom", "min_tokens": 4000}) is True


def test_an_unknown_context_does_not_block_the_harness(monkeypatch):
    # Missing information from ollama.com is not a reason to refuse to run.
    monkeypatch.setattr(ollama, "get_quantization_options", lambda model_name: [])

    assert ollama.check_context_window("qwen3:8b", "claude_code") is True


def test_an_unparseable_context_does_not_block_the_harness(monkeypatch):
    monkeypatch.setattr(
        ollama, "get_quantization_options",
        lambda model_name: [{"context": "?"}])

    assert ollama.check_context_window("qwen3:8b", "claude_code") is True


###########################################################
# Launching a harness
###########################################################

@pytest.fixture
def harness_command(monkeypatch):
    from fakes import RecordingCommand
    monkeypatch.setattr(ollama.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://localhost:11434/")
    return RecordingCommand(monkeypatch)


def test_a_harness_is_launched_against_the_chosen_model(harness_command):
    assert ollama.launch_harness("qwen3:8b", "claude_code") is True
    assert "qwen3:8b" in harness_command.only()


def test_a_harness_is_pointed_at_the_local_server(harness_command):
    ollama.launch_harness("qwen3:8b", "claude_code")

    assert harness_command.options().get_env_var("ANTHROPIC_BASE_URL") == \
        "http://localhost:11434"


def test_an_openai_style_harness_gets_the_versioned_endpoint(harness_command):
    # The base url is stored with a trailing slash often enough that "/v1"
    # appended to it would double the separator.
    ollama.launch_harness("qwen3:8b", "codex")

    assert harness_command.options().get_env_var("OPENAI_BASE_URL") == \
        "http://localhost:11434/v1"


def test_a_harness_runs_in_passthrough(harness_command):
    # The agent is interactive; capturing its output would hang it.
    ollama.launch_harness("qwen3:8b", "claude_code")

    assert harness_command.options().is_passthrough() is True


def test_an_unknown_harness_is_refused(harness_command):
    assert ollama.launch_harness("qwen3:8b", "not-a-harness") is False
    assert harness_command.ran() is False


def test_a_harness_that_is_not_installed_is_refused(monkeypatch):
    from fakes import RecordingCommand
    monkeypatch.setattr(ollama.shutil, "which", lambda name: None)
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://localhost:11434")
    recorder = RecordingCommand(monkeypatch)

    assert ollama.launch_harness("qwen3:8b", "claude_code") is False
    assert recorder.ran() is False


def test_a_failed_harness_reports_failure(monkeypatch):
    from fakes import RecordingCommand
    monkeypatch.setattr(ollama.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://localhost:11434")
    RecordingCommand(monkeypatch, returncode = 1)

    assert ollama.launch_harness("qwen3:8b", "claude_code") is False


###########################################################
# Installed models
###########################################################

def test_installed_models_are_listed_with_their_details(monkeypatch):
    monkeypatch.setattr(ollama.network, "get_remote_json", lambda url: {"models": [{
        "name": "qwen3:8b",
        "size": 5 * (1024 ** 3),
        "details": {
            "family": "qwen3",
            "parameter_size": "8B",
            "quantization_level": "Q4_K_M",
            "format": "gguf",
        },
    }]})

    models = ollama.list_installed_models()

    assert models[0]["name"] == "qwen3:8b"
    assert models[0]["size_gb"] == 5.0
    assert models[0]["quantization"] == "Q4_K_M"


def test_installed_models_are_listed_in_order(monkeypatch):
    monkeypatch.setattr(ollama.network, "get_remote_json", lambda url: {"models": [
        {"name": "qwen3:8b"},
        {"name": "gemma3:12b"},
    ]})

    assert [entry["name"] for entry in ollama.list_installed_models()] == \
        ["gemma3:12b", "qwen3:8b"]


def test_a_model_without_details_still_lists(monkeypatch):
    monkeypatch.setattr(ollama.network, "get_remote_json", lambda url: {"models": [{"name": "bare"}]})

    assert ollama.list_installed_models()[0] == {
        "name": "bare",
        "size_bytes": 0,
        "size_gb": 0.0,
        "family": "",
        "parameter_size": "",
        "quantization": "",
        "format": "",
    }


@pytest.mark.parametrize("response", [None, {}, {"error": "nope"}])
def test_an_unusable_response_lists_nothing(monkeypatch, response):
    monkeypatch.setattr(ollama.network, "get_remote_json", lambda url: response)

    assert ollama.list_installed_models() == []
