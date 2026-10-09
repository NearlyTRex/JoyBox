# Third-party imports
import pytest

# Local imports
from joybox import ollama


###########################################################
# Coding preset
#
# The best coding model the server can hold, with an agent-sized context
# built in, proven to fit by loading it. The catalog, the server and the
# prompts are all faked.
###########################################################

def tag(family, size_tag, size_mb, context = "256K"):
    return {"tag": size_tag, "full_name": "%s:%s" % (family, size_tag),
        "size_str": "%dGB" % (size_mb // 1024), "size_mb": size_mb, "context": context}


MODELS = [
    {"name": "big:120b", "kv_kb_per_token": 72},
    {"name": "dense:24b", "kv_kb_per_token": 160},
    {"name": "moe:30b", "kv_kb_per_token": 96},
    {"name": "short:32b", "kv_kb_per_token": 64},
    {"name": "missing:7b", "kv_kb_per_token": 64},
]

TAGS = {
    "big": [tag("big", "20b", 14336), tag("big", "120b", 66560, "128K")],
    "dense": [tag("dense", "latest", 15360, "384K"), tag("dense", "24b", 15360, "384K")],
    "moe": [tag("moe", "30b", 19456), tag("moe", "30b-q8_0", 32768)],
    "short": [tag("short", "32b", 20480, "32K")],
}


@pytest.fixture
def catalog(monkeypatch):
    state = {"families": []}
    monkeypatch.setattr(ollama, "CODING_MODELS", MODELS)

    def get_model_tags(family):
        state["families"].append(family)
        return TAGS.get(family, [])
    monkeypatch.setattr(ollama, "get_model_tags", get_model_tags)
    return state


###########################################################
# Candidates
###########################################################

def test_the_variant_name_carries_the_context():
    assert ollama.get_context_variant_name("qwen3-coder:30b", 65536) == "qwen3-coder:30b-ctx64k"


@pytest.mark.parametrize("name, tokens", [
    ("qwen3-coder:30b-ctx64k", 65536),
    ("devstral:24b-ctx128k", 131072),
    ("qwen3-coder:30b", None),
    ("model:ctx64k-q4", None),
])
def test_the_window_is_read_back_from_a_variant_name(name, tokens):
    assert ollama.get_variant_context_tokens(name) == tokens


def test_the_loaded_size_counts_weights_context_and_overhead():
    # Measured on the server: qwen3-coder:30b with a 64K window took 30108 MB
    assert abs(ollama.estimate_loaded_mb(19456, 96, 65536) - 30108) < 512


def test_each_card_adds_its_own_overhead():
    # Measured on the server: the same model split over two cards took 31220 MB
    assert abs(ollama.estimate_loaded_mb(19456, 96, 65536, gpu_count = 2) - 31220) < 512


def test_one_card_gets_the_most_capable_models_that_fit(catalog):
    names = [c["full_name"] for c in ollama.get_coding_candidates(32768)]

    assert names == ["dense:24b", "moe:30b"]


def test_more_cards_put_a_larger_model_first(catalog):
    names = [c["full_name"] for c in ollama.get_coding_candidates(3 * 32768)]

    assert names == ["big:120b", "dense:24b", "moe:30b"]


def test_splitting_over_cards_can_leave_a_model_out(catalog):
    # moe:30b fits 31232 MB on one card, but not with a second card's overhead
    assert [c["full_name"] for c in ollama.get_coding_candidates(31232)] == ["dense:24b", "moe:30b"]
    assert [c["full_name"] for c in ollama.get_coding_candidates(31232, gpu_count = 2)] == ["dense:24b"]


def test_the_context_decides_whether_a_model_fits(catalog):
    # 15 GB of weights fits 24 GB, but not once 64K of context is added
    assert [c["full_name"] for c in ollama.get_coding_candidates(24576)] == []
    assert [c["full_name"] for c in ollama.get_coding_candidates(24576, context_tokens = 16384)] == \
        ["dense:24b"]


def test_a_smaller_window_admits_shorter_contexts(catalog):
    names = [c["full_name"] for c in ollama.get_coding_candidates(32768, context_tokens = 32768)]

    assert names == ["dense:24b", "moe:30b", "short:32b"]


def test_a_candidate_carries_its_estimate(catalog):
    candidate = ollama.get_coding_candidates(32768)[0]

    assert candidate["loaded_mb"] == ollama.estimate_loaded_mb(15360, 160, 65536)
    assert candidate["rank"] == 1


def test_each_family_page_is_read_once(catalog, monkeypatch):
    monkeypatch.setattr(ollama, "CODING_MODELS", MODELS + [{"name": "big:20b", "kv_kb_per_token": 48}])

    ollama.get_coding_candidates(32768)

    assert sorted(catalog["families"]) == ["big", "dense", "missing", "moe", "short"]


def test_nothing_fits_a_small_card(catalog):
    assert ollama.get_coding_candidates(4096) == []


def test_the_shipped_list_names_full_tags():
    for entry in ollama.CODING_MODELS:
        assert ":" in entry["name"]
        assert entry["kv_kb_per_token"] > 0


###########################################################
# Server requests
###########################################################

@pytest.fixture
def server(monkeypatch):
    state = {"posts": [], "replies": {}, "ps": {"models": []}}
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://box:11434")

    def post_remote_json(url, data = None, timeout = 10):
        state["posts"].append((url, data, timeout))
        return state["replies"].get(url.rsplit("/", 1)[-1])

    monkeypatch.setattr(ollama.network, "post_remote_json", post_remote_json)
    monkeypatch.setattr(ollama.network, "get_remote_json", lambda url: state["ps"])
    return state


def test_a_variant_is_created_with_the_context_built_in(server):
    server["replies"]["create"] = {"status": "success"}

    assert ollama.create_context_variant("qwen3-coder:30b", 65536) == "qwen3-coder:30b-ctx64k"
    url, data, timeout = server["posts"][-1]
    assert url == "http://box:11434/api/create"
    assert data == {"model": "qwen3-coder:30b-ctx64k", "from": "qwen3-coder:30b",
        "parameters": {"num_ctx": 65536}, "stream": False}


def shown(architecture, context_length):
    return {"model_info": {"general.architecture": architecture,
        "%s.context_length" % architecture: context_length,
        "%s.rope.scaling.original_context_length" % architecture: 8192}}


def test_a_window_past_what_the_model_was_trained_for_is_refused(server):
    # Ollama would cap it silently while still reporting the larger window.
    server["replies"]["show"] = shown("qwen3", 40960)
    server["replies"]["create"] = {"status": "success"}

    assert ollama.create_context_variant("hermes-4:14b", 65536) is None
    assert [url for url, _, _ in server["posts"]] == ["http://box:11434/api/show"]


def test_a_window_within_the_trained_one_is_built(server):
    server["replies"]["show"] = shown("qwen3moe", 262144)
    server["replies"]["create"] = {"status": "success"}

    assert ollama.create_context_variant("qwen3-coder:30b", 65536) == "qwen3-coder:30b-ctx64k"


def test_an_unknown_trained_window_does_not_block_the_variant(server):
    server["replies"]["show"] = {"model_info": {}}
    server["replies"]["create"] = {"status": "success"}

    assert ollama.create_context_variant("qwen3-coder:30b", 65536) == "qwen3-coder:30b-ctx64k"


@pytest.mark.parametrize("reply", [None, {"status": "failed"}])
def test_a_variant_that_is_not_created_is_none(server, reply):
    server["replies"]["create"] = reply

    assert ollama.create_context_variant("qwen3-coder:30b", 65536) is None


def loaded(name, size, size_vram):
    return {"models": [{"name": name, "model": name, "size": size, "size_vram": size_vram}]}


def test_a_model_wholly_in_vram_is_on_the_gpu(server):
    server["replies"]["generate"] = {"done": True}
    server["ps"] = loaded("m:ctx64k", 100, 100)

    assert ollama.is_loaded_on_gpu("m:ctx64k") is True
    url, data, timeout = server["posts"][0]
    assert url == "http://box:11434/api/generate"
    assert data["model"] == "m:ctx64k" and data["prompt"] == ""
    assert timeout >= 600


def test_how_long_it_stays_loaded_is_left_to_the_server(server):
    # A keep_alive sent here would override the server's own setting
    server["replies"]["generate"] = {"done": True}

    ollama.is_loaded_on_gpu("m:ctx64k")

    assert "keep_alive" not in server["posts"][0][1]


@pytest.mark.parametrize("ps", [
    loaded("m:ctx64k", 100, 80),
    loaded("other", 100, 100),
    loaded("m:ctx64k", 0, 0),
    {},
])
def test_a_model_partly_in_ram_or_missing_is_not(server, ps):
    server["replies"]["generate"] = {"done": True}
    server["ps"] = ps

    assert ollama.is_loaded_on_gpu("m:ctx64k") is False


def test_a_model_that_does_not_load_is_not_on_the_gpu(server):
    assert ollama.is_loaded_on_gpu("m:ctx64k") is False


###########################################################
# Preparing a model
###########################################################

@pytest.fixture
def prep(monkeypatch):
    state = {"installed": [], "pulled": [], "created": [], "loaded": [], "fits": set(),
        "answers": [], "asked": []}
    monkeypatch.setattr(ollama, "list_installed_models",
        lambda: [{"name": name} for name in state["installed"]])
    monkeypatch.setattr(ollama, "pull_model",
        lambda name: state["pulled"].append(name) or state["installed"].append(name) or True)

    def create_context_variant(name, context_tokens):
        variant = ollama.get_context_variant_name(name, context_tokens)
        state["created"].append(variant)
        state["installed"].append(variant)
        return variant
    monkeypatch.setattr(ollama, "create_context_variant", create_context_variant)
    monkeypatch.setattr(ollama, "is_loaded_on_gpu",
        lambda name: state["loaded"].append(name) or name in state["fits"])

    def prompt_for_confirmation(message, default_yes = False):
        state["asked"].append(message)
        return state["answers"].pop(0) if state["answers"] else default_yes
    monkeypatch.setattr(ollama.prompts, "prompt_for_confirmation", prompt_for_confirmation)
    return state


def test_a_new_model_is_pulled_given_its_context_and_checked(prep):
    prep["fits"] = {"m:30b-ctx64k"}

    assert ollama.prepare_coding_variant("m:30b", 65536) == "m:30b-ctx64k"
    assert prep["pulled"] == ["m:30b"]
    assert prep["created"] == ["m:30b-ctx64k"]
    assert prep["loaded"] == ["m:30b-ctx64k"]


def test_a_prepared_model_is_only_checked(prep):
    prep["installed"] = ["m:30b", "m:30b-ctx64k"]
    prep["fits"] = {"m:30b-ctx64k"}

    assert ollama.prepare_coding_variant("m:30b", 65536) == "m:30b-ctx64k"
    assert prep["pulled"] == [] and prep["created"] == []
    assert prep["asked"] == []


def test_an_installed_model_only_needs_its_context(prep):
    prep["installed"] = ["m:30b"]
    prep["fits"] = {"m:30b-ctx64k"}

    assert ollama.prepare_coding_variant("m:30b", 65536) == "m:30b-ctx64k"
    assert prep["pulled"] == []
    assert prep["created"] == ["m:30b-ctx64k"]


def test_declining_the_pull_prepares_nothing(prep):
    prep["answers"] = [False]

    assert ollama.prepare_coding_variant("m:30b", 65536) is None
    assert prep["pulled"] == []


def test_a_model_that_spills_out_of_vram_is_not_used(prep):
    assert ollama.prepare_coding_variant("m:30b", 65536) is None
    assert prep["loaded"] == ["m:30b-ctx64k"]


def test_a_failed_pull_prepares_nothing(prep, monkeypatch):
    monkeypatch.setattr(ollama, "pull_model", lambda name: False)

    assert ollama.prepare_coding_variant("m:30b", 65536) is None
    assert prep["created"] == []


def test_a_failed_create_prepares_nothing(prep, monkeypatch):
    monkeypatch.setattr(ollama, "create_context_variant", lambda name, context_tokens: None)

    assert ollama.prepare_coding_variant("m:30b", 65536) is None
    assert prep["loaded"] == []


###########################################################
# Choosing the model
###########################################################

@pytest.fixture
def picker(prep, catalog, monkeypatch):
    monkeypatch.setattr(ollama, "ensure_running", lambda: True)
    monkeypatch.setattr(ollama, "get_server_hardware", lambda: {"gpu_vram_total_mb": 32768, "gpu_count": 1})
    return prep


def test_the_best_candidate_that_fits_is_prepared(picker):
    picker["fits"] = {"dense:24b-ctx64k"}

    assert ollama.prepare_coding_model(ask = False) == "dense:24b-ctx64k"
    assert picker["pulled"] == ["dense:24b"]


def test_the_next_candidate_is_tried_when_one_does_not_fit(picker):
    picker["fits"] = {"moe:30b-ctx64k"}

    assert ollama.prepare_coding_model(ask = False) == "moe:30b-ctx64k"
    assert picker["loaded"] == ["dense:24b-ctx64k", "moe:30b-ctx64k"]


def test_a_better_candidate_is_offered_before_a_prepared_one(picker):
    # More VRAM moves the pick up the list rather than staying on what is there
    picker["installed"] = ["moe:30b", "moe:30b-ctx64k"]
    picker["fits"] = {"moe:30b-ctx64k", "dense:24b-ctx64k"}

    assert ollama.prepare_coding_model() == "dense:24b-ctx64k"
    assert picker["asked"] == ["Pull dense:24b now?"]


def test_declining_the_better_one_falls_back_to_the_prepared_one(picker):
    picker["installed"] = ["moe:30b", "moe:30b-ctx64k"]
    picker["fits"] = {"moe:30b-ctx64k", "dense:24b-ctx64k"}
    picker["answers"] = [False]

    assert ollama.prepare_coding_model() == "moe:30b-ctx64k"
    assert picker["pulled"] == []


def test_the_server_card_count_reaches_the_estimate(picker, monkeypatch):
    monkeypatch.setattr(ollama, "get_server_hardware", lambda: {"gpu_vram_total_mb": 31232, "gpu_count": 2})
    picker["fits"] = {"moe:30b-ctx64k"}

    assert ollama.prepare_coding_model(ask = False) is None
    assert picker["loaded"] == ["dense:24b-ctx64k"]


def test_nothing_is_prepared_when_no_candidate_fits(picker, monkeypatch):
    monkeypatch.setattr(ollama, "get_server_hardware", lambda: {"gpu_vram_total_mb": 4096, "gpu_count": 1})

    assert ollama.prepare_coding_model(ask = False) is None
    assert picker["loaded"] == []


def test_nothing_is_prepared_when_every_candidate_fails(picker):
    assert ollama.prepare_coding_model(ask = False) is None
    assert len(picker["loaded"]) == 2


def test_nothing_is_prepared_without_a_server(picker, monkeypatch):
    monkeypatch.setattr(ollama, "ensure_running", lambda: False)

    assert ollama.prepare_coding_model(ask = False) is None


###########################################################
# The code action
###########################################################

@pytest.fixture
def code(monkeypatch):
    state = {"prepared": [], "launched": [], "variant": "qwen3-coder:30b-ctx64k"}
    monkeypatch.setattr(ollama, "ensure_running", lambda: True)
    monkeypatch.setattr(ollama, "prepare_coding_model",
        lambda context_tokens: state["prepared"].append(("best", context_tokens)) or state["variant"])
    monkeypatch.setattr(ollama, "prepare_coding_variant",
        lambda name, context_tokens: state["prepared"].append((name, context_tokens)) or state["variant"])
    monkeypatch.setattr(ollama, "launch_harness",
        lambda name, harness: state["launched"].append((name, harness)) or True)
    return state


def test_code_starts_claude_code_on_the_best_model(code):
    assert ollama.run_action("code") is True
    assert code["prepared"] == [("best", 65536)]
    assert code["launched"] == [("qwen3-coder:30b-ctx64k", "claude_code")]


def test_code_prepares_a_named_model(code):
    assert ollama.run_action("code", model_name = "devstral:24b", harness = "codex") is True
    assert code["prepared"] == [("devstral:24b", 32768)]
    assert code["launched"] == [("qwen3-coder:30b-ctx64k", "codex")]


@pytest.mark.parametrize("harness, context_tokens", [
    ("claude_code", 65536), ("aider", 32768), ("opencode", 32768), ("codex", 32768)])
def test_only_claude_code_asks_for_a_64k_window(code, harness, context_tokens):
    # A smaller window leaves room for a stronger model
    assert ollama.run_action("code", harness = harness) is True
    assert code["prepared"] == [("best", context_tokens)]


def test_code_launches_nothing_without_a_model(code):
    code["variant"] = None

    assert ollama.run_action("code") is False
    assert code["launched"] == []


def test_code_refuses_an_unknown_harness(code):
    assert ollama.run_action("code", harness = "nope") is False
    assert code["prepared"] == []


def test_code_needs_a_server_for_a_named_model(code, monkeypatch):
    monkeypatch.setattr(ollama, "ensure_running", lambda: False)

    assert ollama.run_action("code", model_name = "devstral:24b") is False
    assert code["prepared"] == []
