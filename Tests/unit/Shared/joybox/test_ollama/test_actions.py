# Third-party imports
import pytest

# Local imports
from joybox import ollama
from ollama_helpers import installed, model



###########################################################
# Actions
#
# These are what the CLI runs, and each one either deletes a model, starts a
# multi-gigabyte download or hands the terminal to an agent. What is pinned
# is that nothing happens without the answer that asked for it.
###########################################################

@pytest.fixture
def console(monkeypatch):
    # The server, the hardware and the prompts, all declared by the test.
    state = {
        "running": True,
        "installed": [],
        "answers": [],
        "selections": [],
        "pulled": [],
        "deleted": [],
        "launched": [],
        "info": "Model info",
        "hardware": {
            "gpu_vram_total_mb": 8000,
            "gpu_vram_free_mb": 6000,
            "system_ram_mb": 32000,
        },
        "prompted": [],
    }

    monkeypatch.setattr(ollama, "ensure_running", lambda: state["running"])
    monkeypatch.setattr(ollama, "is_running", lambda: state["running"])
    monkeypatch.setattr(ollama, "list_installed_models", lambda: state["installed"])
    monkeypatch.setattr(ollama, "show_model", lambda name: state["info"])
    monkeypatch.setattr(
        ollama, "delete_model", lambda name: state["deleted"].append(name) or True)
    monkeypatch.setattr(
        ollama, "pull_with_quantization",
        lambda name: state["pulled"].append(name) or True)
    monkeypatch.setattr(
        ollama, "launch_harness",
        lambda name, harness: state["launched"].append((name, harness)) or True)
    monkeypatch.setattr(
        ollama.hardware, "get_hardware_summary", lambda: state["hardware"])
    monkeypatch.setattr(ollama.hardware, "print_hardware_summary", lambda: None)
    monkeypatch.setattr(ollama, "check_context_window", lambda name, harness: True)

    def prompt_for_confirmation(message, default_yes = False):
        state["prompted"].append(message)
        if state["answers"]:
            return state["answers"].pop(0)
        return False

    def prompt_for_selection(message, options, display_func = None):
        state["prompted"].append(message)
        if state["selections"]:
            index = state["selections"].pop(0)
            return None if index is None else options[index]
        return None

    monkeypatch.setattr(ollama.prompts, "prompt_for_confirmation", prompt_for_confirmation)
    monkeypatch.setattr(ollama.prompts, "prompt_for_selection", prompt_for_selection)
    return state


###########################################################
# Listing
###########################################################

def test_listing_reports_the_installed_models(console):
    console["installed"] = [installed()]

    assert ollama.action_list() is True


def test_listing_with_nothing_installed_is_not_a_failure(console):
    assert ollama.action_list() is True


def test_nothing_is_listed_without_a_server(console):
    console["running"] = False

    assert ollama.action_list() is False


###########################################################
# Deleting
###########################################################

def test_a_named_model_is_deleted_once_confirmed(console):
    console["answers"] = [True]

    assert ollama.action_delete(model_name = "qwen3:8b") is True
    assert console["deleted"] == ["qwen3:8b"]


def test_nothing_is_deleted_without_confirmation(console):
    # The confirmation is the only thing between a typo and a lost download.
    console["answers"] = [False]

    assert ollama.action_delete(model_name = "qwen3:8b") is True
    assert console["deleted"] == []


def test_a_model_to_delete_can_be_chosen_from_the_installed_ones(console):
    console["installed"] = [installed("qwen3:8b"), installed("gemma3:12b")]
    console["selections"] = [1]
    console["answers"] = [True]

    ollama.action_delete()

    assert console["deleted"] == ["gemma3:12b"]


def test_declining_the_selection_deletes_nothing(console):
    console["installed"] = [installed()]
    console["selections"] = [None]

    assert ollama.action_delete() is True
    assert console["deleted"] == []


def test_deleting_with_nothing_installed_is_not_a_failure(console):
    assert ollama.action_delete() is True
    assert console["deleted"] == []


def test_a_failed_delete_reports_failure(console, monkeypatch):
    monkeypatch.setattr(ollama, "delete_model", lambda name: False)
    console["answers"] = [True]

    assert ollama.action_delete(model_name = "qwen3:8b") is False


def test_nothing_is_deleted_without_a_server(console):
    console["running"] = False

    assert ollama.action_delete(model_name = "qwen3:8b") is False
    assert console["deleted"] == []


###########################################################
# Model information
###########################################################

def test_information_is_shown_for_a_named_model(console):
    assert ollama.action_info(model_name = "qwen3:8b") is True


def test_a_model_to_inspect_can_be_chosen(console):
    console["installed"] = [installed("qwen3:8b")]
    console["selections"] = [0]

    assert ollama.action_info() is True


def test_a_model_with_no_information_reports_failure(console, monkeypatch):
    monkeypatch.setattr(ollama, "show_model", lambda name: None)

    assert ollama.action_info(model_name = "qwen3:8b") is False


def test_inspecting_with_nothing_installed_is_not_a_failure(console):
    assert ollama.action_info() is True


###########################################################
# Pulling
###########################################################

def test_a_named_model_is_pulled(console):
    assert ollama.action_pull(model_name = "qwen3:8b") is True
    assert console["pulled"] == ["qwen3:8b"]


def test_pulling_without_a_name_offers_what_is_available(console, monkeypatch):
    # Rather than failing, the CLI shows the catalogue to choose from.
    shown = []
    monkeypatch.setattr(
        ollama, "action_available",
        lambda **kwargs: shown.append(kwargs) or True)

    assert ollama.action_pull() is True
    assert shown


def test_nothing_is_pulled_without_a_server(console):
    console["running"] = False

    assert ollama.action_pull(model_name = "qwen3:8b") is False
    assert console["pulled"] == []


###########################################################
# Recommending
###########################################################

@pytest.fixture
def catalog(monkeypatch):
    entries = []
    monkeypatch.setattr(ollama, "get_model_catalog", lambda purpose = None: entries)
    return entries


def test_the_best_model_is_reported(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000, purpose = ollama.PURPOSE_TOOLS))

    assert ollama.action_best() is True


def test_the_best_model_can_be_pulled_on_confirmation(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000, purpose = ollama.PURPOSE_TOOLS))
    console["answers"] = [True]

    ollama.action_best()

    assert console["pulled"] == ["gpu:8b"]


def test_an_already_installed_best_model_is_not_pulled_again(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000, purpose = ollama.PURPOSE_TOOLS))
    console["installed"] = [installed("gpu:8b")]

    assert ollama.action_best() is True
    assert console["pulled"] == []


def test_nothing_fitting_the_hardware_is_not_a_failure(console, catalog):
    # A small machine should be told so rather than shown an error.
    catalog.append(model(name = "huge:70b", vram_mb = 64000, purpose = ollama.PURPOSE_TOOLS))

    assert ollama.action_best() is True
    assert console["pulled"] == []


###########################################################
# Launching a harness
###########################################################

def test_a_harness_is_launched_with_an_installed_model(console):
    console["installed"] = [installed("qwen3:8b")]

    assert ollama.action_harness(model_name = "qwen3:8b") is True
    assert console["launched"] == [("qwen3:8b", ollama.DEFAULT_HARNESS)]


def test_a_harness_can_be_chosen_by_name(console):
    console["installed"] = [installed("qwen3:8b")]

    ollama.action_harness(model_name = "qwen3:8b", harness = "codex")

    assert console["launched"] == [("qwen3:8b", "codex")]


def test_an_unknown_harness_is_not_launched(console):
    console["installed"] = [installed()]

    assert ollama.action_harness(model_name = "qwen3:8b", harness = "nope") is False
    assert console["launched"] == []


def test_a_model_to_run_can_be_chosen_from_the_installed_ones(console):
    console["installed"] = [installed("qwen3:8b"), installed("gemma3:12b")]
    console["selections"] = [1]

    ollama.action_harness()

    assert console["launched"] == [("gemma3:12b", ollama.DEFAULT_HARNESS)]


def test_declining_the_model_selection_launches_nothing(console):
    console["installed"] = [installed()]
    console["selections"] = [None]

    assert ollama.action_harness() is True
    assert console["launched"] == []


def test_a_harness_needs_something_installed(console):
    assert ollama.action_harness() is False
    assert console["launched"] == []


def test_a_model_that_is_not_installed_is_offered_for_pulling(console):
    console["installed"] = [installed("qwen3:8b")]
    console["answers"] = [True]

    assert ollama.action_harness(model_name = "gemma3:12b") is True
    assert console["pulled"] == ["gemma3:12b"]


def test_declining_to_pull_does_not_launch(console):
    console["installed"] = [installed("qwen3:8b")]
    console["answers"] = [False]

    assert ollama.action_harness(model_name = "gemma3:12b") is False
    assert console["launched"] == []


def test_a_short_context_window_asks_before_launching(console, monkeypatch):
    # The agent will truncate its own conversation, so the warning is worth
    # stopping for.
    monkeypatch.setattr(ollama, "check_context_window", lambda name, harness: False)
    console["installed"] = [installed("qwen3:8b")]
    console["answers"] = [False]

    assert ollama.action_harness(model_name = "qwen3:8b") is True
    assert console["launched"] == []


def test_a_short_context_window_can_be_accepted(console, monkeypatch):
    monkeypatch.setattr(ollama, "check_context_window", lambda name, harness: False)
    console["installed"] = [installed("qwen3:8b")]
    console["answers"] = [True]

    ollama.action_harness(model_name = "qwen3:8b")

    assert console["launched"] == [("qwen3:8b", ollama.DEFAULT_HARNESS)]


def test_no_harness_is_launched_without_a_server(console):
    console["running"] = False

    assert ollama.action_harness(model_name = "qwen3:8b") is False
    assert console["launched"] == []


###########################################################
# Available models
###########################################################

def test_the_available_models_are_shown(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000))

    assert ollama.action_available(purpose = ollama.PURPOSE_CHAT) is True


def test_a_purpose_can_be_chosen_when_none_was_given(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000))
    console["selections"] = [0]

    assert ollama.action_available() is True


def test_declining_the_purpose_shows_nothing(console, catalog):
    console["selections"] = [None]

    assert ollama.action_available() is True


def test_an_available_model_can_be_pulled(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000))
    console["answers"] = [True]
    console["selections"] = [0]

    ollama.action_available(purpose = ollama.PURPOSE_CHAT)

    assert console["pulled"] == ["gpu:8b"]


def test_an_installed_model_is_not_offered_for_pulling(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000))
    console["installed"] = [installed("gpu:8b")]
    console["answers"] = [True]

    ollama.action_available(purpose = ollama.PURPOSE_CHAT)

    assert console["pulled"] == []


def test_a_model_too_large_is_not_offered_for_pulling(console, catalog):
    # Pulling it would download gigabytes that cannot be loaded.
    catalog.append(model(name = "huge:70b", vram_mb = 64000))
    console["answers"] = [True]

    ollama.action_available(purpose = ollama.PURPOSE_CHAT)

    assert console["pulled"] == []


def test_an_empty_catalogue_is_not_a_failure(console, catalog):
    assert ollama.action_available(purpose = ollama.PURPOSE_CHAT) is True


###########################################################
# Dispatch
###########################################################

def test_every_action_can_be_dispatched_by_name(console, catalog):
    for action in ollama.get_action_keys():
        assert ollama.run_action(action) is not None


###########################################################
# Available model listing
###########################################################

@pytest.fixture
def logged(monkeypatch):
    lines = []
    monkeypatch.setattr(ollama.logger, "log_info", lambda message: lines.append(message))
    return lines


def test_every_fit_is_marked_in_the_full_listing(console, catalog, logged):
    catalog.extend([
        model(name = "mine:8b", vram_mb = 4000),
        model(name = "gpu:8b", vram_mb = 4000),
        model(name = "slow:30b", vram_mb = 20000),
        model(name = "remote", vram_mb = 0, cloud_only = True),
        model(name = "huge:70b", vram_mb = 64000),
    ])
    console["installed"] = [installed("mine:8b")]

    assert ollama.action_available(purpose = ollama.PURPOSE_CHAT, show_all = True) is True

    text = "\n".join(logged)
    assert "[*] mine:8b" in text
    assert "[+] gpu:8b" in text
    assert "[~] slow:30b" in text
    assert "(CPU offload, slower)" in text
    assert "[C] remote (cloud-hosted)" in text
    assert "[-] huge:70b" in text
    assert "ollama pull remote" not in text
    assert "Use --all" not in text


def test_nothing_is_marked_installed_without_a_server(console, catalog, logged):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000))
    console["installed"] = [installed("gpu:8b")]
    console["running"] = False

    ollama.action_available(purpose = ollama.PURPOSE_CHAT)

    assert any("[+] gpu:8b" in line for line in logged)


def test_declining_the_model_to_pull_pulls_nothing(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000))
    console["answers"] = [True]
    console["selections"] = [None]

    assert ollama.action_available(purpose = ollama.PURPOSE_CHAT) is True
    assert console["pulled"] == []


def test_a_failed_pull_from_the_listing_is_a_failure(console, catalog, monkeypatch):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000))
    console["answers"] = [True]
    console["selections"] = [0]
    monkeypatch.setattr(ollama, "pull_with_quantization", lambda name: False)

    assert ollama.action_available(purpose = ollama.PURPOSE_CHAT) is False


###########################################################
# Remaining action outcomes
###########################################################

def test_no_information_is_shown_without_a_server(console):
    console["running"] = False

    assert ollama.action_info(model_name = "qwen3:8b") is False


def test_declining_the_model_to_inspect_is_not_a_failure(console, monkeypatch):
    monkeypatch.setattr(ollama, "show_model", lambda name: pytest.fail("shown"))
    console["installed"] = [installed()]
    console["selections"] = [None]

    assert ollama.action_info() is True


def test_a_failed_pull_does_not_launch_the_harness(console, monkeypatch):
    monkeypatch.setattr(ollama, "pull_with_quantization", lambda name: False)
    console["installed"] = [installed("qwen3:8b")]
    console["answers"] = [True]

    assert ollama.action_harness(model_name = "gemma3:12b") is False
    assert console["launched"] == []


def test_the_best_model_is_offered_when_the_server_is_down(console, catalog):
    catalog.append(model(name = "gpu:8b", vram_mb = 4000, purpose = ollama.PURPOSE_TOOLS))
    console["installed"] = [installed("gpu:8b")]
    console["running"] = False
    console["answers"] = [True]

    ollama.action_best()

    assert console["pulled"] == ["gpu:8b"]


def test_an_offloaded_best_model_is_reported_as_slower(console, catalog, logged):
    catalog.append(model(name = "slow:30b", vram_mb = 20000, purpose = ollama.PURPOSE_TOOLS))

    assert ollama.action_best() is True
    assert any("CPU offload (slower)" in line for line in logged)
