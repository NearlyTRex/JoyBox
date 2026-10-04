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

    assert harness_command.options().get_env_var("CODEX_OSS_BASE_URL") == \
        "http://localhost:11434/v1"


def test_codex_uses_its_own_ollama_provider(harness_command):
    ollama.launch_harness("qwen3:8b", "codex")

    assert harness_command.only() == ["codex", "--oss", "--local-provider", "ollama", "-m", "qwen3:8b"]


def test_codex_is_told_the_window_built_into_a_variant(harness_command):
    ollama.launch_harness("qwen3-coder:30b-ctx64k", "codex")

    assert harness_command.only()[-2:] == ["-c", "model_context_window=65536"]


def test_opencode_is_given_a_provider_for_the_server(harness_command):
    import json
    ollama.launch_harness("qwen3-coder:30b-ctx64k", "opencode")

    assert harness_command.only() == ["opencode", "--model", "ollama/qwen3-coder:30b-ctx64k"]
    config = json.loads(harness_command.options().get_env_var("OPENCODE_CONFIG_CONTENT"))
    provider = config["provider"]["ollama"]
    assert provider["options"]["baseURL"] == "http://localhost:11434/v1"
    assert provider["models"]["qwen3-coder:30b-ctx64k"] == {
        "name": "qwen3-coder:30b-ctx64k", "tools": True,
        "limit": {"context": 65536, "output": 8192}}


def test_opencode_leaves_an_unknown_window_to_the_server(harness_command):
    import json
    ollama.launch_harness("qwen3:8b", "opencode")

    config = json.loads(harness_command.options().get_env_var("OPENCODE_CONFIG_CONTENT"))
    assert "limit" not in config["provider"]["ollama"]["models"]["qwen3:8b"]


def launched(harness_command):
    # The last command is the harness; preflight checks may have run before it
    return harness_command.calls[-1]["cmd"]


def test_aider_talks_to_the_server_natively(harness_command):
    ollama.launch_harness("qwen3:8b", "aider")

    assert launched(harness_command) == [
        "aider", "--model", "ollama_chat/qwen3:8b", "--no-show-model-warnings"]
    assert harness_command.options(-1).get_env_var("OLLAMA_API_BASE") == "http://localhost:11434"


@pytest.fixture
def cache_root(monkeypatch, tmp_path):
    monkeypatch.setattr(ollama.environment, "get_cache_root_dir", lambda: str(tmp_path))
    return tmp_path


def test_aider_keeps_a_variant_window_fixed(harness_command, cache_root):
    # aider would otherwise size num_ctx to each request, and ollama reloads
    # the model whenever it changes
    ollama.launch_harness("devstral-small-2:24b-ctx32k", "aider")

    command_line = launched(harness_command)
    assert command_line[-2] == "--model-settings-file"
    settings_file = cache_root / "Ollama" / "aider" / "devstral-small-2_24b-ctx32k.model-settings.yml"
    assert command_line[-1] == str(settings_file)
    assert settings_file.read_text() == (
        "- name: ollama_chat/devstral-small-2:24b-ctx32k\n"
        "  extra_params:\n"
        "    num_ctx: 32768\n")


def test_aider_without_a_known_window_gets_no_settings(cache_root):
    assert ollama.build_aider_args("http://box:11434", "qwen3:8b") == []
    assert not (cache_root / "Ollama").exists()


def test_unwritable_aider_settings_leave_aider_to_size_it(cache_root, monkeypatch):
    monkeypatch.setattr(ollama.serialization, "write_text_file", lambda src, contents: False)

    assert ollama.build_aider_args("http://box:11434", "m:ctx32k", 32768) == []


def test_claude_code_is_told_the_window_built_into_a_variant(harness_command):
    # It would otherwise assume a window far larger than the model holds
    ollama.launch_harness("qwen3-coder:30b-ctx64k", "claude_code")

    assert harness_command.options().get_env_var("CLAUDE_CODE_MAX_CONTEXT_TOKENS") == "65536"


def test_a_model_without_a_built_in_window_sets_none(harness_command):
    ollama.launch_harness("qwen3:8b", "claude_code")

    assert harness_command.options().get_env_var("CLAUDE_CODE_MAX_CONTEXT_TOKENS") is None


def test_a_harness_without_a_window_setting_is_not_given_one(harness_command):
    ollama.launch_harness("qwen3-coder:30b-ctx64k", "codex")

    assert harness_command.options().get_env_var("CLAUDE_CODE_MAX_CONTEXT_TOKENS") is None


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


def test_a_missing_harness_binary_is_not_run(harness_command, monkeypatch):
    monkeypatch.setattr(ollama.shutil, "which", lambda name: None)

    assert ollama.launch_harness("qwen3:8b", "claude_code") is False
    assert harness_command.ran() is False


def test_a_missing_binary_without_an_install_hint_is_still_refused(harness_command, monkeypatch):
    monkeypatch.setattr(ollama.shutil, "which", lambda name: None)
    spec = dict(ollama.HARNESSES["codex"])
    del spec["install_hint"]
    monkeypatch.setitem(ollama.HARNESSES, "codex", spec)

    assert ollama.launch_harness("qwen3:8b", "codex") is False


###########################################################
# Preflight
#
# aider reads git through GitPython's own reader, which only opens packs named
# pack-*.pack; git's loose-objects maintenance writes loose-*.pack, and aider
# then calls the repository corrupt and quits.
###########################################################

def make_packs(directory, *names):
    directory.mkdir(parents = True, exist_ok = True)
    for name in names:
        (directory / name).write_bytes(b"")
    return directory


def test_only_ordinary_packs_are_readable(tmp_path):
    pack_dir = make_packs(tmp_path / "pack",
        "pack-aaa.pack", "pack-aaa.idx", "loose-bbb.pack", "loose-bbb.idx", "multi-pack-index")

    assert ollama.get_unreadable_packs(str(pack_dir)) == ["loose-bbb.pack"]


def test_a_missing_pack_dir_has_nothing_unreadable(tmp_path):
    assert ollama.get_unreadable_packs(str(tmp_path / "absent")) == []


@pytest.fixture
def git(monkeypatch, tmp_path):
    state = {"pack_dir": make_packs(tmp_path / "objects" / "pack", "pack-aaa.pack"),
        "rev_parse": None, "repack_code": 0, "repack_leaves": [], "commands": []}
    monkeypatch.setattr(ollama.programs, "get_tool_program", lambda name: "git")

    def run_command(cmd, options = None, **kwargs):
        state["commands"].append(cmd)
        if state["rev_parse"] is not None:
            return state["rev_parse"]
        return (str(state["pack_dir"]) + "\n", 0)

    def run_returncode_command(cmd, options = None, **kwargs):
        state["commands"].append(cmd)
        if state["repack_code"] == 0:
            for path in state["pack_dir"].glob("loose-*"):
                if path.name not in state["repack_leaves"]:
                    path.unlink()
        return state["repack_code"]

    monkeypatch.setattr(ollama.command, "run_command", run_command)
    monkeypatch.setattr(ollama.command, "run_returncode_command", run_returncode_command)
    return state


def test_a_readable_repository_is_left_alone(git):
    assert ollama.prepare_git_for_aider() is True
    assert git["commands"] == [["git", "rev-parse", "--path-format=absolute", "--git-path", "objects/pack"]]


def test_outside_a_repository_there_is_nothing_to_do(git):
    git["rev_parse"] = ("fatal: not a git repository\n", 128)

    assert ollama.prepare_git_for_aider() is True
    assert len(git["commands"]) == 1


def test_unreadable_packs_are_repacked(git):
    make_packs(git["pack_dir"], "loose-bbb.pack")

    assert ollama.prepare_git_for_aider() is True
    assert git["commands"][-1] == ["git", "repack", "-a", "-d"]
    assert ollama.get_unreadable_packs(str(git["pack_dir"])) == []


def test_a_failed_repack_stops_the_launch(git):
    make_packs(git["pack_dir"], "loose-bbb.pack")
    git["repack_code"] = 1

    assert ollama.prepare_git_for_aider() is False


def test_packs_still_unreadable_after_repacking_stop_the_launch(git):
    make_packs(git["pack_dir"], "loose-bbb.pack")
    git["repack_leaves"] = ["loose-bbb.pack"]

    assert ollama.prepare_git_for_aider() is False


def test_aider_checks_the_repository_before_starting():
    assert ollama.prepare_git_for_aider in ollama.HARNESSES["aider"]["preflight"]


def test_a_failed_preflight_launches_nothing(harness_command, monkeypatch):
    monkeypatch.setitem(ollama.HARNESSES["aider"], "preflight", [lambda: False])

    assert ollama.launch_harness("qwen3:8b", "aider") is False
    assert harness_command.ran() is False


def test_a_passed_preflight_launches(harness_command, monkeypatch):
    checked = []
    monkeypatch.setitem(ollama.HARNESSES["aider"], "preflight", [lambda: checked.append(True) or True])

    assert ollama.launch_harness("qwen3:8b", "aider") is True
    assert checked == [True]
    assert launched(harness_command)[0] == "aider"
