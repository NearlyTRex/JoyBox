# Third-party imports
import pytest

# Local imports
from joybox import ollama
from joybox import ollamacatalog
from joybox import ollamaagents
from joybox import ollamaactions
from fakes import RecordingCommand


###########################################################
# Updating the server
###########################################################

@pytest.fixture
def updating(tunneled, monkeypatch):
    state = {"versions": ["0.35.1", None, "0.36.0"], "slept": 0}
    monkeypatch.setattr(ollamaactions, "get_server_version", lambda: state["versions"].pop(0) if state["versions"] else None)
    monkeypatch.setattr(ollama.runtime, "sleep_program", lambda seconds: state.update(slept = state["slept"] + 1))
    return state


def test_update_reruns_the_installer_on_the_server(updating, recording_command):
    assert ollamaactions.action_update() is True
    assert recording_command.only() == ["ssh", "testuser@llm", ollamaactions.OLLAMA_INSTALL_COMMAND]


def test_update_waits_for_the_server_to_answer_again(updating, recording_command):
    ollamaactions.action_update()

    assert updating["versions"] == []
    assert updating["slept"] == 1


def test_update_needs_the_ssh_host(updating, recording_command, tunneled):
    tunneled["ollama_ssh_host"] = ""

    assert ollamaactions.action_update() is False
    assert recording_command.ran() is False


def test_a_failed_installer_fails_the_update(updating, monkeypatch):
    RecordingCommand(monkeypatch, returncode = 1)

    assert ollamaactions.action_update() is False


def test_a_server_that_does_not_come_back_fails_the_update(updating, recording_command):
    updating["versions"] = ["0.35.1"]

    assert ollamaactions.action_update() is False
    assert updating["slept"] == 30


def test_the_server_version_is_read_from_the_api(monkeypatch):
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://localhost:11444")
    monkeypatch.setattr(ollama.network, "get_remote_json",
        lambda url: {"version": "0.35.1"} if url == "http://localhost:11444/api/version" else None)

    assert ollamaactions.get_server_version() == "0.35.1"


###########################################################
# Pulling with a quantization choice
###########################################################

@pytest.fixture
def puller(monkeypatch):
    state = {"options": [], "selection": None, "pulled": [], "result": True, "shown": []}
    monkeypatch.setattr(ollama, "read_helper_report", lambda: None)
    monkeypatch.setattr(ollama.hardware, "get_hardware_summary", lambda: {
        "gpu_vram_total_mb": 8000, "system_ram_mb": 32000})
    monkeypatch.setattr(ollamacatalog, "get_quantization_options", lambda name: state["options"])
    monkeypatch.setattr(
        ollama, "pull_model", lambda name: state["pulled"].append(name) or state["result"])

    def prompt_for_selection(message, options, display_func = None):
        state["shown"] = [display_func(o) for o in options]
        return None if state["selection"] is None else options[state["selection"]]
    monkeypatch.setattr(ollamaagents.prompts, "prompt_for_selection", prompt_for_selection)
    return state


def quant(full_name, size_mb):
    return {"full_name": full_name, "size_mb": size_mb, "size_str": "?", "context": "40K"}


def test_a_model_with_one_quantization_is_pulled_as_named(puller):
    puller["options"] = [quant("qwen3:8b", 5000)]

    assert ollamaactions.pull_with_quantization("qwen3:8b") is True
    assert puller["pulled"] == ["qwen3:8b"]


def test_the_chosen_quantization_is_pulled(puller):
    puller["options"] = [quant("qwen3:8b", 5000), quant("qwen3:8b-fp16", 16000)]
    puller["selection"] = 1

    assert ollamaactions.pull_with_quantization("qwen3:8b") is True
    assert puller["pulled"] == ["qwen3:8b-fp16"]
    assert puller["shown"][0].startswith("[+]")
    assert puller["shown"][1].startswith("[~]")


def test_declining_the_quantization_pulls_nothing(puller):
    puller["options"] = [quant("qwen3:8b", 5000), quant("qwen3:8b-fp16", 16000)]

    assert ollamaactions.pull_with_quantization("qwen3:8b") is True
    assert puller["pulled"] == []


def test_a_failed_pull_is_reported(puller):
    puller["result"] = False

    assert ollamaactions.pull_with_quantization("qwen3:8b") is False
