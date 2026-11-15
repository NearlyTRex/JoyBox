# Coding agents on an Ollama model: the harnesses that run against the server,
# and preparing a coding model that fits it.

# Imports
import json
import os
import re
import shutil

# Local imports
from joybox import command
from joybox import environment
from joybox import logger
from joybox import network
from joybox import ollama
from joybox import ollamacatalog
from joybox import programs
from joybox import prompts
from joybox import serialization

###########################################################
# Coding-agent harness integration
###########################################################

# Build OpenCode's provider config for a model on the Ollama server
# OpenCode has no ollama provider of its own and reads its config from this
# variable as well as from files, so nothing is written to the user's config.
def build_opencode_config(api_base, model_name, context_tokens = None):
    model = {"name": model_name, "tools": True}
    if context_tokens:
        model["limit"] = {"context": context_tokens, "output": 8192}
    return json.dumps({
        "$schema": "https://opencode.ai/config.json",
        "provider": {"ollama": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "Ollama",
            "options": {"baseURL": api_base + "/v1"},
            "models": {model_name: model}}}})

# List the packs in a pack directory that GitPython's own reader cannot see
# It only opens packs named pack-*.pack, and git's loose-objects maintenance
# writes loose-*.pack beside them.
def get_unreadable_packs(pack_dir):
    try:
        names = os.listdir(pack_dir)
    except OSError:
        return []
    return sorted(name for name in names if name.endswith(".pack") and not name.startswith("pack-"))

# Make the repository here readable by aider, whose GitPython reader calls it corrupt
# over a pack it cannot see, by repacking into one ordinary pack when needed
def prepare_git_for_aider():
    git_tool = programs.get_tool_program("Git")
    output, code = command.run_command(
        [git_tool, "rev-parse", "--path-format=absolute", "--git-path", "objects/pack"])
    if code != 0 or not output:
        return True
    pack_dir = output.strip()
    unreadable = get_unreadable_packs(pack_dir)
    if not unreadable:
        return True
    logger.log_info("Repacking the repository so aider can read it (%s)" % ", ".join(unreadable))
    if command.run_returncode_command([git_tool, "repack", "-a", "-d"]) != 0:
        logger.log_error("git repack failed; aider would report the repository as corrupt")
        return False
    remaining = get_unreadable_packs(pack_dir)
    if remaining:
        logger.log_error("Packs aider cannot read are still there after repacking: %s" % ", ".join(remaining))
        return False
    return True

# Write aider's settings for a model on the Ollama server, returning its arguments;
# num_ctx is fixed at the variant's window, since ollama reloads the model, a minute
# or more, whenever aider's per-request num_ctx changes
def build_aider_args(api_base, model_name, context_tokens = None):
    if not context_tokens:
        return []
    settings_file = os.path.join(
        environment.get_cache_root_dir(), "Ollama", "aider",
        re.sub(r"[^A-Za-z0-9._-]", "_", model_name) + ".model-settings.yml")
    contents = "- name: ollama_chat/%s\n  extra_params:\n    num_ctx: %d\n" % (model_name, context_tokens)
    if not serialization.write_text_file(settings_file, contents):
        logger.log_warning("Could not write %s; aider will size the context itself" % settings_file)
        return []
    return ["--model-settings-file", settings_file]

###########################################################
# Harnesses
#
# Coding-agent CLIs that can run against a model on the Ollama server. Each
# entry gives:
#
#   name            display name
#   min_tokens      smallest window worth running it with (check_context_window)
#   command, env    how to start it and point it at the server
#   context_args,   added only when the model is a -ctxNNk variant, so its
#   context_env     window is known
#   arg_builders,   called with (api_base, model, context) for what a
#   env_builders    template cannot express
#   preflight       checks run in its working directory before it starts;
#                   one returning False stops the launch
#   coding_context  the window the code action builds a variant with
#   install_hint    shown when its command is not on the PATH
#
# In the templates, "{model}" is the model name, "{api_base}" the server's
# base URL and "{context}" the window built into a -ctxNNk variant.
#
# Claude Code and Hermes Agent need 64K; the rest get 32K, which leaves room
# for a stronger model. aider and opencode send far less with each request
# than the others, which suits local models.
###########################################################

HARNESSES = {

    # Claude Code
    #
    # Talks to Ollama's Anthropic-compatible endpoint. It assumes a window of
    # its own for a model it does not know, far past what a local one holds,
    # and would not compact in time, so a variant's window is passed in.
    "claude_code": {
        "name": "Claude Code",
        "min_tokens": 64000,
        "command": ["claude", "--model", "{model}", "--bare"],
        "env": {
            "ANTHROPIC_BASE_URL": "{api_base}",
            "ANTHROPIC_API_KEY": "ollama",
            "ANTHROPIC_AUTH_TOKEN": "",
        },
        "context_env": "CLAUDE_CODE_MAX_CONTEXT_TOKENS",
        "coding_context": 65536,
        "install_hint": "https://docs.claude.com/claude-code",
    },

    # Codex CLI
    #
    # Its built-in ollama provider cannot be redefined, only pointed at the
    # server's /v1 endpoint. --oss alone still puts up the ChatGPT sign-in,
    # which model_provider skips. The bootstrap installs it globally as root,
    # so its own updater fails and is turned off.
    "codex": {
        "name": "Codex CLI",
        "min_tokens": 8000,
        "command": ["codex", "--oss", "--local-provider", "ollama", "-m", "{model}",
            "-c", "model_provider=ollama",
            "-c", "check_for_update_on_startup=false"],
        "env": {"CODEX_OSS_BASE_URL": "{api_base}/v1"},
        "context_args": ["-c", "model_context_window={context}"],
        "coding_context": 32768,
        "install_hint": "npm install -g @openai/codex",
    },

    # OpenCode
    #
    # Given an ollama provider on the server's /v1 endpoint through
    # OPENCODE_CONFIG_CONTENT (build_opencode_config), so nothing is written to
    # its config.
    "opencode": {
        "name": "OpenCode",
        "min_tokens": 8000,
        "command": ["opencode", "--model", "ollama/{model}"],
        "env_builders": {"OPENCODE_CONFIG_CONTENT": build_opencode_config},
        "coding_context": 32768,
        "install_hint": "npm install -g opencode-ai",
    },

    # Aider
    #
    # Talks to Ollama's native API. A variant's window is fixed in a
    # model-settings file (build_aider_args), and a repository it cannot read
    # is repacked first (prepare_git_for_aider).
    "aider": {
        "name": "Aider",
        "min_tokens": 8000,
        "command": ["aider", "--model", "ollama_chat/{model}", "--no-show-model-warnings"],
        "env": {"OLLAMA_API_BASE": "{api_base}"},
        "arg_builders": [build_aider_args],
        "preflight": [prepare_git_for_aider],
        "coding_context": 32768,
        "install_hint": "the Python installer puts it in a venv of its own (bootstrap); it pins its dependencies, so not into a shared venv",
    },

    # Hermes Agent
    #
    # Its custom provider reads the server's /v1 endpoint from CUSTOM_BASE_URL,
    # so nothing is written to ~/.hermes, which keeps its memory and skills
    # between runs. It refuses a window under 64K and takes the window from
    # /api/show, which only a -ctxNNk variant's num_ctx makes match what the
    # server serves.
    "hermes": {
        "name": "Hermes Agent",
        "min_tokens": 64000,
        "command": ["hermes", "--provider", "custom", "-m", "{model}"],
        "env": {"CUSTOM_BASE_URL": "{api_base}/v1"},
        "coding_context": 65536,
        "install_hint": "the bootstrap's hermes component (a pinned release in a venv of its own)",
    },
}

# Default harness when none is specified
DEFAULT_HARNESS = "claude_code"

# List available harness keys
def get_harness_keys():
    return sorted(HARNESSES.keys())

# Whether a model's context window meets a requirement, a harness key or a dict of
# "name" and "min_tokens"; True when the window is unknown, False with a warning
# when it falls short
def check_context_window(model_name, requirement):
    req = HARNESSES[requirement] if isinstance(requirement, str) else requirement
    name = req["name"]
    min_tokens = req["min_tokens"]
    quant_options = ollamacatalog.get_quantization_options(model_name)
    if not quant_options:
        logger.log_info("Context info unavailable, proceeding.")
        return True
    context_str = quant_options[0].get("context", "")
    context_tokens = ollamacatalog.parse_context_tokens(context_str)
    if context_tokens <= 0:
        logger.log_info("Context info unavailable, proceeding.")
        return True
    if context_tokens < min_tokens:
        logger.log_warning("%s reports a %s context window (%d tokens). %s recommends at least %d tokens - responses may be truncated." % (
            model_name, context_str, context_tokens, name, min_tokens))
        return False
    logger.log_info("Context window: %s (%d tokens) - OK." % (context_str, context_tokens))
    return True

# Launch a coding-agent harness against an Ollama model. harness is a key into
# HARNESSES (defaults to DEFAULT_HARNESS). Fills the command/env templates,
# points the harness at the Ollama server, and runs it in passthrough mode.
def launch_harness(model_name, harness = DEFAULT_HARNESS):
    spec = HARNESSES.get(harness)
    if not spec:
        logger.log_error("Unknown harness '%s'. Available: %s" % (harness, ", ".join(get_harness_keys())))
        return False

    # Fill templates ({api_base} without trailing slash so "{api_base}/v1" is clean)
    api_base = ollama.get_api_base().rstrip("/")
    context_tokens = get_variant_context_tokens(model_name)
    def fill(value):
        return value.replace("{api_base}", api_base).replace("{model}", model_name) \
            .replace("{context}", str(context_tokens or ""))
    cmd = [fill(part) for part in spec["command"]]
    if context_tokens:
        cmd += [fill(part) for part in spec.get("context_args", [])]
    for build in spec.get("arg_builders", []):
        cmd += build(api_base, model_name, context_tokens)

    # Require the harness binary to be installed
    if not shutil.which(cmd[0]):
        logger.log_error("%s is not installed (command '%s' not found)" % (spec["name"], cmd[0]))
        if spec.get("install_hint"):
            logger.log_info("Install: %s" % spec["install_hint"])
        return False

    # Put right whatever would stop the harness once it is running
    for check in spec.get("preflight", []):
        if not check():
            return False

    options = command.create_command_options()
    for key, value in spec.get("env", {}).items():
        options.set_env_var(key, fill(value))
    for key, build in spec.get("env_builders", {}).items():
        options.set_env_var(key, build(api_base, model_name, context_tokens))
    if context_tokens and spec.get("context_env"):
        options.set_env_var(spec["context_env"], str(context_tokens))
    options.set_passthrough(True)
    return command.run_returncode_command(cmd, options = options) == 0

###########################################################
# Coding preset
#
# One command to a coding model that suits the server: the best one whose
# download fits the GPUs, given a context window big enough for an agent and
# checked by loading it and asking ollama where it went.
###########################################################

# Coding models, most capable first
# Each carries roughly how much VRAM its context takes per token, from its
# layer and key/value head counts or, where it has been loaded on the server,
# from what it actually took, so a model is not downloaded only to find the
# window does not fit beside it. Loading it is still the final check. Ollama
# keeps a full window for each request it serves at once, so the counts are
# for the two the server is set up for.
# Dense models come before mixture-of-experts ones of a similar size, which
# answer quickly but use a fraction of their weights on each token and are
# shakier at the multi-step work an agent does.
CODING_MODELS = [
    {"name": "devstral-2:123b", "kv_kb_per_token": 704},
    {"name": "gpt-oss:120b", "kv_kb_per_token": 72},
    {"name": "qwen3-coder-next:latest", "kv_kb_per_token": 32},
    {"name": "devstral-small-2:24b", "kv_kb_per_token": 304},
    {"name": "qwen3-coder:30b", "kv_kb_per_token": 180},
    {"name": "gpt-oss:20b", "kv_kb_per_token": 48},
    {"name": "devstral:24b", "kv_kb_per_token": 304},
]

# Context window the preset asks for unless a harness asks for another
CODING_CONTEXT_TOKENS = 65536

# What a loaded model takes beyond its weights and context on each card it is
# split across, measured against models loaded on the server; it does not
# grow with the weights
LOAD_OVERHEAD_MB = 1024

# Estimate the VRAM a model takes once loaded with a context window
def estimate_loaded_mb(size_mb, kv_kb_per_token, context_tokens, gpu_count = 1):
    return int(size_mb + LOAD_OVERHEAD_MB * gpu_count + kv_kb_per_token * context_tokens / 1024)

# Name of a model with the context window built in
def get_context_variant_name(model_name, context_tokens):
    return "%s-ctx%dk" % (model_name, context_tokens // 1024)

# Read the context window built into a variant's name, or None
def get_variant_context_tokens(model_name):
    match = re.search(r"-ctx(\d+)k$", model_name)
    return int(match.group(1)) * 1024 if match else None

# List coding models that could fit, most capable first
def get_coding_candidates(vram_mb, context_tokens = CODING_CONTEXT_TOKENS, gpu_count = 1):
    candidates = []
    tags_by_family = {}
    for rank, entry in enumerate(CODING_MODELS):
        family = entry["name"].split(":", 1)[0]
        if family not in tags_by_family:
            tags_by_family[family] = ollamacatalog.get_model_tags(family)
        tag = next((t for t in tags_by_family[family] if t["full_name"] == entry["name"]), None)
        if not tag:
            continue
        if ollamacatalog.parse_context_tokens(tag["context"]) < context_tokens:
            continue
        loaded_mb = estimate_loaded_mb(tag["size_mb"], entry["kv_kb_per_token"], context_tokens, gpu_count)
        if loaded_mb > vram_mb:
            continue
        candidates.append(dict(tag, rank = rank, loaded_mb = loaded_mb))
    return candidates

# Read the context window a model was trained for, or None when unknown
def get_trained_context_tokens(model_name):
    shown = network.post_remote_json(ollama.get_api_base() + "/api/show", data = {"model": model_name}, timeout = 30)
    info = (shown or {}).get("model_info") or {}
    trained = info.get("%s.context_length" % info.get("general.architecture"))
    return trained if isinstance(trained, int) and trained > 0 else None

# Create a model with the context window built in, for agents that cannot pass
# num_ctx; a window past the trained one is refused, since ollama would quietly
# cap it while reporting the larger size
def create_context_variant(model_name, context_tokens):
    variant = get_context_variant_name(model_name, context_tokens)
    trained = get_trained_context_tokens(model_name)
    if trained and context_tokens > trained:
        logger.log_error("%s was trained for %d tokens, short of the %dK asked for" % (
            model_name, trained, context_tokens // 1024))
        return None
    result = network.post_remote_json(
        ollama.get_api_base() + "/api/create",
        data = {"model": variant, "from": model_name,
            "parameters": {"num_ctx": context_tokens}, "stream": False},
        timeout = 120)
    if not result or result.get("status") != "success":
        logger.log_error("Could not create %s from %s" % (variant, model_name))
        return None
    return variant

# Load a model and report whether it sits wholly in VRAM
# How long it then stays loaded is left to the server's own setting.
def is_loaded_on_gpu(model_name):
    loaded = network.post_remote_json(
        ollama.get_api_base() + "/api/generate",
        data = {"model": model_name, "prompt": "", "stream": False},
        timeout = 900)
    if loaded is None:
        logger.log_error("%s did not load" % model_name)
        return False
    running = network.get_remote_json(ollama.get_api_base() + "/api/ps") or {}
    for entry in running.get("models", []):
        if entry.get("name") == model_name or entry.get("model") == model_name:
            size = entry.get("size", 0)
            return size > 0 and entry.get("size_vram", 0) >= size
    return False

# Prepare a named model for coding: pulled, its context built in, and on the GPUs
def prepare_coding_variant(model_name, context_tokens = CODING_CONTEXT_TOKENS, ask = True):
    installed = {m["name"] for m in ollama.list_installed_models()}
    variant = get_context_variant_name(model_name, context_tokens)
    if variant not in installed:
        if model_name not in installed:
            if ask and not prompts.prompt_for_confirmation("Pull %s now?" % model_name, default_yes = True):
                return None
            if not ollama.pull_model(model_name):
                return None
        if not create_context_variant(model_name, context_tokens):
            return None
    logger.log_info("Loading %s to check it fits the GPUs..." % variant)
    if not is_loaded_on_gpu(variant):
        logger.log_warning("%s does not fit wholly in VRAM with a %dK context" % (variant, context_tokens // 1024))
        return None
    return variant

# Find the best coding model for the server and prepare it, most capable first; a
# declined pull falls back to the next, and one prepared earlier is only loaded
def prepare_coding_model(context_tokens = CODING_CONTEXT_TOKENS, ask = True):
    if not ollama.ensure_running():
        return None
    hw = ollama.get_server_hardware()
    candidates = get_coding_candidates(hw["gpu_vram_total_mb"], context_tokens, hw["gpu_count"])
    if not candidates:
        logger.log_error("No coding model fits %d MB of VRAM with a %dK context" % (
            hw["gpu_vram_total_mb"], context_tokens // 1024))
        return None
    for candidate in candidates:
        logger.log_info("Trying %s (%s download, ~%d MB loaded with a %dK context) for %d MB of VRAM" % (
            candidate["full_name"], candidate["size_str"], candidate["loaded_mb"],
            context_tokens // 1024, hw["gpu_vram_total_mb"]))
        variant = prepare_coding_variant(candidate["full_name"], context_tokens, ask = ask)
        if variant:
            return variant
    logger.log_error("None of the coding models could be prepared")
    return None
