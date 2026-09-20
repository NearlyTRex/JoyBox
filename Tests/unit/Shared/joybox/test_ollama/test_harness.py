# Third-party imports
import pytest

# Local imports
from joybox import ollama



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
