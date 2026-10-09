# Imports
import json
import os
import re
import shutil
import urllib.parse

# Local imports
import joybox.command as command
import joybox.environment as environment
import joybox.logger as logger
import joybox.network as network
import joybox.hardware as hardware
import joybox.programs as programs
import joybox.prompts as prompts
import joybox.serialization as serialization
import joybox.settings as settings
from joybox import runtime

###########################################################
# Ollama API
###########################################################

# Default Ollama API base URL (used when the setting is unset)
OLLAMA_API_BASE_DEFAULT = "http://localhost:11434"

# Get the configured Ollama API base URL (falls back to the local default)
def get_api_base():
    return settings.get_value("Tools.Ollama", "ollama_api_base", OLLAMA_API_BASE_DEFAULT, throw_exception = False)

# Check if Ollama is running
def is_running():
    return network.is_url_reachable(get_api_base())

# Get the SSH destination of the server, when it is reached through a tunnel
# The server's API then listens on its own localhost, and the base URL is the
# local end of the tunnel (the bootstrap's ollama_tunnel component).
def get_ssh_host():
    return settings.get_value("Tools.Ollama", "ollama_ssh_host", "", throw_exception = False) or ""

# Check if the server is reached through an SSH tunnel
def is_tunneled():
    return bool(get_ssh_host())

# Check if the configured server is this machine
# A tunnel's local end is on localhost too, but the server is not.
def is_local_server():
    if is_tunneled():
        return False
    host = urllib.parse.urlparse(get_api_base()).hostname or ""
    return host in ("localhost", "::1", "0.0.0.0") or host.startswith("127.")

# Options for the ollama command, aimed at the configured server
# The command ignores the setting and reads OLLAMA_HOST instead.
def create_client_options():
    options = command.create_command_options()
    options.set_env_var("OLLAMA_HOST", get_api_base())
    return options

# Read a size in megabytes from the settings, or None when unset
def get_setting_mb(field):
    value = str(settings.get_value("Tools.Ollama", field, "", throw_exception = False) or "").strip()
    if not value:
        return None
    if not value.isdigit():
        logger.log_warning("Ignoring [Tools.Ollama] %s, which is not a whole number of megabytes: %s" % (field, value))
        return None
    return int(value)

# Port the helper beside the server reports its hardware on
HELPER_PORT = 11435

# Read the hardware report from the helper beside the server, or None
# ollama's API says nothing about GPUs, so the LLM server image runs a helper
# that does; any other server simply has none.
def read_helper_report():
    host = urllib.parse.urlparse(get_api_base()).hostname
    if not host:
        return None
    if ":" in host:
        host = "[%s]" % host
    report = network.get_remote_json("http://%s:%d/hardware" % (host, HELPER_PORT))
    if not isinstance(report, dict) or "compute_vram_total_mb" not in report:
        return None
    return report

# Get the hardware the configured server runs models on
# Sizes set in the settings win, then the server's helper report, then this
# machine, which is only right when the server is local.
def get_server_hardware():
    hw = dict(hardware.get_hardware_summary(), gpu_count = 1)
    report = read_helper_report()
    if report:
        names = [gpu.get("name", "?") for gpu in report.get("gpus", []) if gpu.get("compute")]
        hw.update(
            gpu_name = ", ".join(names) or "None detected",
            gpu_vram_total_mb = report["compute_vram_total_mb"],
            gpu_vram_free_mb = report.get("compute_vram_free_mb", 0),
            gpu_count = max(report.get("compute_gpu_count", 1), 1),
            system_ram_mb = report.get("ram_total_mb", 0),
            system_ram_available_mb = report.get("ram_available_mb", 0))
    vram_mb = get_setting_mb("ollama_gpu_vram_mb")
    ram_mb = get_setting_mb("ollama_system_ram_mb")
    if vram_mb is not None:
        hw.update(gpu_name = "Configured for %s" % get_api_base(),
            gpu_vram_total_mb = vram_mb, gpu_vram_free_mb = vram_mb)
    elif not report and not is_local_server():
        logger.log_warning(
            "Fits are judged against this machine, not the server at %s, which has no "
            "hardware helper; set [Tools.Ollama] ollama_gpu_vram_mb to the server's VRAM" % get_api_base())
    if ram_mb is not None:
        hw.update(system_ram_mb = ram_mb, system_ram_available_mb = ram_mb)
    return hw

# Start Ollama serve in the background
# A server on another machine cannot be started from here.
def start_serve():
    if is_running():
        return True
    if not is_local_server():
        logger.log_error("Ollama server at %s is not answering" % get_api_base())
        if is_tunneled():
            logger.log_info("It is reached through an SSH tunnel to %s; check it with: systemctl --user status ollama-tunnel" % get_ssh_host())
        return False
    logger.log_info("Starting Ollama server...")
    options = command.create_command_options()
    options.set_is_daemon(True)
    command.run_returncode_command(["ollama", "serve"], options = options)
    for _ in range(10):
        runtime.sleep_program(1)
        if is_running():
            logger.log_info("Ollama server started")
            return True
    logger.log_error("Ollama server failed to start")
    return False

# Ensure Ollama is running, starting it if needed
def ensure_running():
    if is_running():
        return True
    return start_serve()

# List installed models
def list_installed_models():
    result = network.get_remote_json(get_api_base() + "/api/tags")
    if not result or "models" not in result:
        return []
    models = []
    for m in result["models"]:
        details = m.get("details", {})
        models.append({
            "name": m.get("name", ""),
            "size_bytes": m.get("size", 0),
            "size_gb": round(m.get("size", 0) / (1024 ** 3), 1),
            "family": details.get("family", ""),
            "parameter_size": details.get("parameter_size", ""),
            "quantization": details.get("quantization_level", ""),
            "format": details.get("format", ""),
        })
    return sorted(models, key = lambda x: x["name"])

# Pull (download) a model. Runs in passthrough mode so ollama's native progress
# bar streams live to the terminal during multi-GB downloads.
def pull_model(model_name):
    options = create_client_options()
    options.set_passthrough(True)
    code = command.run_returncode_command(
        ["ollama", "pull", model_name],
        options = options)
    return code == 0

# Delete a model
def delete_model(model_name):
    code = command.run_returncode_command(
        ["ollama", "rm", model_name],
        options = create_client_options())
    return code == 0

# Show model info
def show_model(model_name):
    output = command.run_output_command(
        ["ollama", "show", model_name],
        options = create_client_options())
    if output:
        return output
    return None

###########################################################
# Model catalog
###########################################################

# Purpose categories (aligned with Ollama's capabilities)
PURPOSE_CHAT = "chat"
PURPOSE_TOOLS = "tools"
PURPOSE_REASONING = "reasoning"
PURPOSE_VISION = "vision"
PURPOSE_EMBEDDING = "embedding"
PURPOSE_CLOUD = "cloud"
ALL_PURPOSES = [
    PURPOSE_CHAT,
    PURPOSE_TOOLS,
    PURPOSE_REASONING,
    PURPOSE_VISION,
    PURPOSE_EMBEDDING,
    PURPOSE_CLOUD,
]
PURPOSE_DESCRIPTIONS = {
    PURPOSE_CHAT: "General chat and conversation",
    PURPOSE_TOOLS: "Tool use, coding, and agentic tasks",
    PURPOSE_REASONING: "Complex reasoning and analysis",
    PURPOSE_VISION: "Image understanding and description",
    PURPOSE_EMBEDDING: "Text embeddings for search/RAG",
    PURPOSE_CLOUD: "Cloud-hosted models",
}

# Map Ollama capabilities to our purpose categories
CAPABILITY_TO_PURPOSE = {
    "tools": PURPOSE_TOOLS,
    "thinking": PURPOSE_REASONING,
    "vision": PURPOSE_VISION,
    "embedding": PURPOSE_EMBEDDING,
    "cloud": PURPOSE_CLOUD,
}

# Ollama search categories to query for each purpose
PURPOSE_TO_SEARCH = {
    PURPOSE_CHAT: "",
    PURPOSE_TOOLS: "tools",
    PURPOSE_REASONING: "thinking",
    PURPOSE_VISION: "vision",
    PURPOSE_EMBEDDING: "embedding",
    PURPOSE_CLOUD: "cloud",
}

# Approximate VRAM (MB) per billion parameters at Q4_K_M quantization
VRAM_MB_PER_BILLION_PARAMS = 620

# Estimate VRAM requirement from parameter size string (e.g. "7b", "0.5b", "120b")
def estimate_vram_mb(param_str):
    param_str = param_str.lower().strip()
    match = re.match(r'^([\d.]+)([bm]?)$', param_str)
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2)
    if unit == "m" or (unit == "" and value > 500):
        return int(value / 1000 * VRAM_MB_PER_BILLION_PARAMS)
    return int(value * VRAM_MB_PER_BILLION_PARAMS)

# Parse a compact parameter-count string (e.g. "14B", "400M") into billions,
# for ranking models by size. Returns 0.0 if unparseable (e.g. "?").
def parse_param_count(param_str):
    match = re.match(r'^([\d.]+)([bm]?)$', str(param_str).lower().strip())
    if not match:
        return 0.0
    value = float(match.group(1))
    if match.group(2) == "m":
        return value / 1000
    return value

# Parse a context-window string (e.g. "128K", "8192") into a token count
def parse_context_tokens(context_str):
    match = re.match(r'^([\d.]+)([km]?)$', str(context_str).lower().strip())
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2)
    if unit == "k":
        return int(value * 1024)
    if unit == "m":
        return int(value * 1024 * 1024)
    return int(value)

# Parse model entries from Ollama search HTML. When filter_purpose is set (a
# server-side ?c=<purpose> filter was applied), every entry is assigned that
# purpose — needed for filters like "cloud" that aren't model-level capability
# tags (cloud models still advertise tools/thinking/vision). Otherwise the
# purpose is inferred from capability tags.
def parse_search_html(html, filter_purpose = None):
    models = []
    blocks = re.split(r'<a href="/library/', html)
    for block in blocks[1:]:
        name_match = re.search(r'^([^"]+)', block)
        if not name_match:
            continue
        base_name = name_match.group(1)
        desc_match = re.search(r'<p class="max-w-lg[^>]*>(.*?)</p>', block, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else ""

        # Decode HTML entities
        description = description.replace("&#39;", "'").replace("&amp;", "&").replace("&quot;", '"')
        caps = re.findall(r'x-test-capability[^>]*>([^<]+)</span>', block)
        sizes = re.findall(r'x-test-size[^>]*>([^<]+)</span>', block)
        pulls_match = re.search(r'x-test-pull-count[^>]*>([^<]+)</span>', block)
        pulls = pulls_match.group(1).strip() if pulls_match else ""

        # Determine purpose: honor a server-side ?c= filter, else infer from caps
        if filter_purpose:
            purpose = filter_purpose
        else:
            purpose = PURPOSE_CHAT
            for cap in caps:
                cap = cap.strip().lower()
                if cap in CAPABILITY_TO_PURPOSE:
                    purpose = CAPABILITY_TO_PURPOSE[cap]
                    break

        # Create an entry for each available size
        if sizes:
            for size in sizes:
                size = size.strip().lower()
                vram = estimate_vram_mb(size)
                models.append({
                    "name": "%s:%s" % (base_name, size),
                    "display": "%s %s" % (base_name, size.upper()),
                    "purpose": purpose,
                    "params": size.upper(),
                    "vram_mb": vram,
                    "description": description,
                    "pulls": pulls,
                })
        else:
            # No downloadable size variants = cloud-only model. Flag it so the fit
            # logic renders it as cloud instead of "too large for hardware".
            models.append({
                "name": base_name,
                "display": base_name,
                "purpose": purpose,
                "params": "?",
                "vram_mb": 0,
                "cloud_only": True,
                "description": description,
                "pulls": pulls,
            })
    return models

# Fetch models from Ollama search for a given purpose
def fetch_remote_models(purpose = None):
    search_cat = PURPOSE_TO_SEARCH.get(purpose, "") if purpose else ""
    url = "https://ollama.com/search"
    if search_cat:
        url += "?c=%s" % search_cat
    html = network.get_remote_html(url, headers = {"HX-Request": "true"})
    if html:
        return parse_search_html(html, filter_purpose = purpose if search_cat else None)
    return []

# Cache for remote catalog
remote_catalog_cache = {}

# Get model catalog - fetches from ollama.com, falls back to hardcoded
def get_model_catalog(purpose = None):
    cache_key = purpose or "__all__"
    if cache_key in remote_catalog_cache:
        return remote_catalog_cache[cache_key]

    # Try remote first
    models = fetch_remote_models(purpose)
    if models:
        remote_catalog_cache[cache_key] = models
        return models

    # Fall back to hardcoded
    logger.log_warning("Could not fetch models from ollama.com, using built-in catalog")
    if purpose:
        return [m for m in FALLBACK_CATALOG if m["purpose"] == purpose]
    return FALLBACK_CATALOG

# Fallback hardcoded catalog (used when ollama.com is unreachable)
FALLBACK_CATALOG = [
    {"name": "llama3.1:8b",        "display": "Llama 3.1 8B",             "purpose": PURPOSE_CHAT,      "params": "8B",   "vram_mb": 5000,  "description": "Meta's versatile general-purpose model"},
    {"name": "gemma3:12b",         "display": "Gemma 3 12B",              "purpose": PURPOSE_CHAT,      "params": "12B",  "vram_mb": 8000,  "description": "Google's mid-size model"},
    {"name": "qwen3:8b",           "display": "Qwen 3 8B",                "purpose": PURPOSE_CHAT,      "params": "8B",   "vram_mb": 5000,  "description": "Alibaba's versatile model"},
    {"name": "qwen2.5-coder:7b",   "display": "Qwen 2.5 Coder 7B",       "purpose": PURPOSE_TOOLS,    "params": "7B",   "vram_mb": 4500,  "description": "Strong code generation and completion"},
    {"name": "qwen2.5-coder:14b",  "display": "Qwen 2.5 Coder 14B",      "purpose": PURPOSE_TOOLS,    "params": "14B",  "vram_mb": 9000,  "description": "Larger coding model with better reasoning"},
    {"name": "qwen2.5-coder:32b",  "display": "Qwen 2.5 Coder 32B",      "purpose": PURPOSE_TOOLS,    "params": "32B",  "vram_mb": 20000, "description": "Top-tier open coding model"},
    {"name": "deepseek-r1:14b",    "display": "DeepSeek R1 14B",          "purpose": PURPOSE_REASONING, "params": "14B",  "vram_mb": 9000,  "description": "Strong reasoning at mid-size"},
    {"name": "deepseek-r1:32b",    "display": "DeepSeek R1 32B",          "purpose": PURPOSE_REASONING, "params": "32B",  "vram_mb": 20000, "description": "Excellent reasoning, needs beefy GPU"},
    {"name": "llava:7b",           "display": "LLaVA 7B",                 "purpose": PURPOSE_VISION,    "params": "7B",   "vram_mb": 5000,  "description": "Image understanding and Q&A"},
    {"name": "nomic-embed-text",   "display": "Nomic Embed Text",         "purpose": PURPOSE_EMBEDDING, "params": "137M", "vram_mb": 300,   "description": "Fast text embeddings for search/RAG"},
]

###########################################################
# Model tags / quantization
###########################################################

# Bytes in each unit of a size string; ollama.com prints decimal units
SIZE_UNIT_BYTES = {"KB": 10 ** 3, "MB": 10 ** 6, "GB": 10 ** 9, "TB": 10 ** 12}

# Parse size string like "5.2GB", "890MB" to MB, the binary megabytes
# nvidia-smi reports VRAM in
def parse_size_to_mb(size_str):
    size_str = size_str.strip().upper()
    match = re.match(r'^([\d.]+)\s*(GB|MB|KB|TB)$', size_str)
    if not match:
        return 0
    return max(1, int(float(match.group(1)) * SIZE_UNIT_BYTES[match.group(2)] / (1024 * 1024)))

# Fetch available tags (quantizations) for a model
def get_model_tags(base_name):

    # Strip any existing tag to get the model family name
    model_family = base_name.split(":")[0]
    url = "https://ollama.com/library/%s/tags" % model_family
    html = network.get_remote_html(url, headers = {"HX-Request": "true"})
    if not html:
        return []

    # Parse tag entries: tag name, size, context window
    pattern = r'href="/library/%s:([^"]+)"[^>]*class="md:hidden.*?(\d+(?:\.\d+)?(?:GB|MB|KB|TB))\s*.*?(\d+K?) context window' % re.escape(model_family)
    matches = re.findall(pattern, html, re.DOTALL)
    tags = []
    seen = set()
    for tag, size_str, context in matches:
        if tag in seen:
            continue
        seen.add(tag)
        size_mb = parse_size_to_mb(size_str)
        tags.append({
            "tag": tag,
            "full_name": "%s:%s" % (model_family, tag),
            "size_str": size_str,
            "size_mb": size_mb,
            "context": context,
        })
    return tags

# Get tags filtered to a specific parameter size (e.g. "8b")
def get_quantization_options(base_name):

    # Extract the size part (e.g. "8b" from "qwen3:8b")
    parts = base_name.split(":")
    if len(parts) < 2:
        return []
    size_tag = parts[1].lower()
    all_tags = get_model_tags(base_name)

    # Filter to tags that start with the size (e.g. "8b", "8b-q4_K_M", "8b-q8_0", "8b-fp16")
    options = []
    for tag in all_tags:
        tag_name = tag["tag"].lower()
        if tag_name == size_tag or tag_name.startswith(size_tag + "-"):

            # Determine quantization label
            if "-" in tag["tag"]:
                quant = tag["tag"].split("-", 1)[1]
            else:
                quant = "default"
            tag["quantization"] = quant
            options.append(tag)
    return options

# Format quantization option for display
def format_quantization_display(option, vram_mb = 0, ram_mb = 0):
    size_mb = option["size_mb"]
    if vram_mb > 0 and size_mb <= vram_mb:
        prefix = "+"
    elif ram_mb > 0 and size_mb <= ram_mb:
        prefix = "~"
    else:
        prefix = "-"
    return "[%s] %s (%s, %s context)" % (
        prefix,
        option["full_name"],
        option["size_str"],
        option["context"]
    )

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

# Make the repository here readable by aider, repacking when it needs to be
# aider reads git through GitPython's own reader, and an object in a pack it
# cannot see makes aider call the repository corrupt and quit. Repacking puts
# every object into one ordinary pack and changes nothing else.
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

# Write aider's settings for a model on the Ollama server, returning its arguments
# Left to itself, aider sends a num_ctx sized to each request, and ollama
# reloads the model whenever num_ctx changes, which on a slow link to the GPU
# is a minute or more per message. Fixing it at the window built into the
# variant keeps the loaded model in place.
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

# Verify a model's reported context window meets a harness's recommended minimum.
# The requirement is either a harness key (e.g. "claude_code") or a dict with
# "name" and "min_tokens". Returns True if the model meets the minimum or the
# context info is unavailable (so callers don't abort on missing data); False
# (with a warning) if it falls short.
def check_context_window(model_name, requirement):
    req = HARNESSES[requirement] if isinstance(requirement, str) else requirement
    name = req["name"]
    min_tokens = req["min_tokens"]
    quant_options = get_quantization_options(model_name)
    if not quant_options:
        logger.log_info("Context info unavailable, proceeding.")
        return True
    context_str = quant_options[0].get("context", "")
    context_tokens = parse_context_tokens(context_str)
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
    api_base = get_api_base().rstrip("/")
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
            tags_by_family[family] = get_model_tags(family)
        tag = next((t for t in tags_by_family[family] if t["full_name"] == entry["name"]), None)
        if not tag:
            continue
        if parse_context_tokens(tag["context"]) < context_tokens:
            continue
        loaded_mb = estimate_loaded_mb(tag["size_mb"], entry["kv_kb_per_token"], context_tokens, gpu_count)
        if loaded_mb > vram_mb:
            continue
        candidates.append(dict(tag, rank = rank, loaded_mb = loaded_mb))
    return candidates

# Read the context window a model was trained for, or None when unknown
def get_trained_context_tokens(model_name):
    shown = network.post_remote_json(get_api_base() + "/api/show", data = {"model": model_name}, timeout = 30)
    info = (shown or {}).get("model_info") or {}
    trained = info.get("%s.context_length" % info.get("general.architecture"))
    return trained if isinstance(trained, int) and trained > 0 else None

# Create a model with the context window built in
# Agents cannot pass num_ctx with each request, and the server's default is
# far smaller than they need. Ollama quietly caps num_ctx at the trained
# window while still reporting the larger one, so an agent sizing itself from
# that report would overrun the model; such a window is refused instead.
def create_context_variant(model_name, context_tokens):
    variant = get_context_variant_name(model_name, context_tokens)
    trained = get_trained_context_tokens(model_name)
    if trained and context_tokens > trained:
        logger.log_error("%s was trained for %d tokens, short of the %dK asked for" % (
            model_name, trained, context_tokens // 1024))
        return None
    result = network.post_remote_json(
        get_api_base() + "/api/create",
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
        get_api_base() + "/api/generate",
        data = {"model": model_name, "prompt": "", "stream": False},
        timeout = 900)
    if loaded is None:
        logger.log_error("%s did not load" % model_name)
        return False
    running = network.get_remote_json(get_api_base() + "/api/ps") or {}
    for entry in running.get("models", []):
        if entry.get("name") == model_name or entry.get("model") == model_name:
            size = entry.get("size", 0)
            return size > 0 and entry.get("size_vram", 0) >= size
    return False

# Prepare a named model for coding: pulled, its context built in, and on the GPUs
def prepare_coding_variant(model_name, context_tokens = CODING_CONTEXT_TOKENS, ask = True):
    installed = {m["name"] for m in list_installed_models()}
    variant = get_context_variant_name(model_name, context_tokens)
    if variant not in installed:
        if model_name not in installed:
            if ask and not prompts.prompt_for_confirmation("Pull %s now?" % model_name, default_yes = True):
                return None
            if not pull_model(model_name):
                return None
        if not create_context_variant(model_name, context_tokens):
            return None
    logger.log_info("Loading %s to check it fits the GPUs..." % variant)
    if not is_loaded_on_gpu(variant):
        logger.log_warning("%s does not fit wholly in VRAM with a %dK context" % (variant, context_tokens // 1024))
        return None
    return variant

# Find the best coding model for the server and prepare it
# Candidates are tried most capable first, so a server given more VRAM moves
# up the list. Declining to pull one falls back to the next, which may be one
# prepared earlier; a prepared model is only loaded, so it starts at once.
def prepare_coding_model(context_tokens = CODING_CONTEXT_TOKENS, ask = True):
    if not ensure_running():
        return None
    hw = get_server_hardware()
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

###########################################################
# Recommendation logic
###########################################################

# Fit categories
FIT_GPU = "gpu"           # Fits entirely in VRAM
FIT_OFFLOAD = "offload"   # Exceeds VRAM but fits in system RAM (CPU offload)
FIT_NONE = "none"         # Exceeds both VRAM and RAM
FIT_CLOUD = "cloud"       # Cloud-hosted (no local download; hardware fit N/A)

# Display/sort order (best fit first)
FIT_ORDER = [FIT_GPU, FIT_OFFLOAD, FIT_CLOUD, FIT_NONE]

# Get models with fit classification based on VRAM and RAM. By default, models
# too large for the hardware (FIT_NONE) and cloud-hosted models (FIT_CLOUD) are
# excluded, since neither is runnable on local hardware; set include_unfit /
# include_cloud to include them. A PURPOSE_CLOUD query forces include_cloud on.
def get_recommended_models(purpose = None, vram_mb = None, ram_mb = None, include_unfit = False, include_cloud = False):
    if purpose == PURPOSE_CLOUD:
        include_cloud = True
    if vram_mb is None or ram_mb is None:
        hw = get_server_hardware()
        if vram_mb is None:
            vram_mb = hw["gpu_vram_total_mb"]
        if ram_mb is None:
            ram_mb = hw["system_ram_mb"]
    catalog = get_model_catalog(purpose)
    models = []
    for model in catalog:
        if purpose and model["purpose"] != purpose:
            continue
        model_entry = model.copy()
        if model.get("cloud_only"):
            model_entry["fit"] = FIT_CLOUD
        elif model["vram_mb"] <= 0:
            model_entry["fit"] = FIT_NONE
        elif vram_mb > 0 and model["vram_mb"] <= vram_mb:
            model_entry["fit"] = FIT_GPU
        elif ram_mb > 0 and model["vram_mb"] <= ram_mb:
            model_entry["fit"] = FIT_OFFLOAD
        else:
            model_entry["fit"] = FIT_NONE
        model_entry["fits_vram"] = model_entry["fit"] == FIT_GPU
        if not include_unfit and model_entry["fit"] == FIT_NONE:
            continue
        if not include_cloud and model_entry["fit"] == FIT_CLOUD:
            continue
        models.append(model_entry)
    fit_rank = {fit: i for i, fit in enumerate(FIT_ORDER)}
    models.sort(key = lambda m: fit_rank.get(m["fit"], len(FIT_ORDER)))
    return models

# Auto-pick the best locally-runnable model for a purpose: highest fit tier
# (GPU before offload), then largest parameter count within that tier. Returns
# None if nothing fits the available hardware (caller can then widen the search).
def get_best_model(purpose = PURPOSE_TOOLS, vram_mb = None, ram_mb = None):
    local = get_recommended_models(purpose = purpose, vram_mb = vram_mb, ram_mb = ram_mb)
    if not local:
        return None
    for fit_tier in (FIT_GPU, FIT_OFFLOAD):
        tier = [m for m in local if m["fit"] == fit_tier]
        if tier:
            return max(tier, key = lambda m: parse_param_count(m["params"]))
    return None

# Format model for display in selection list
def format_model_display(model):
    fit_marker = "+" if model.get("fits_vram", True) else "-"
    vram_gb = model["vram_mb"] / 1024
    return "[%s] %s (%s, ~%.1f GB VRAM) - %s" % (
        fit_marker,
        model["display"],
        model["params"],
        vram_gb,
        model["description"]
    )

# Format installed model for display
def format_installed_model_display(model):
    return "%s (%.1f GB, %s %s)" % (
        model["name"],
        model["size_gb"],
        model["parameter_size"],
        model["quantization"]
    )

###########################################################
# Actions
#
# Every action takes the same keyword signature so the CLI can dispatch without
# knowing which options a given action cares about.
###########################################################

# Pull a model, offering a quantization choice when the model has several
# Check if a tag is a raw completion model
# Base and text tags continue text rather than follow a conversation, so they
# cannot drive a chat or call tools.
def is_completion_only_tag(tag):
    return re.search(r"(^|-)(base|text)(-|$)", tag.lower()) is not None

# Choose which quantization of a model to pull
# Returns the full name chosen, the name itself when there is no choice to
# make, or None when the choice is declined.
def choose_quantization(model_name, chat_only = False):
    options = get_quantization_options(model_name)
    if chat_only:
        options = [o for o in options if not is_completion_only_tag(o["tag"])]
    if len(options) <= 1:
        return options[0]["full_name"] if options else model_name
    hw = get_server_hardware()
    logger.log_info("Available quantizations for %s:" % model_name)
    logger.log_info("[+] fits GPU  [~] CPU offload  [-] too large")
    selected = prompts.prompt_for_selection(
        "Select quantization:",
        options,
        display_func = lambda o: format_quantization_display(o, hw["gpu_vram_total_mb"], hw["system_ram_mb"])
    )
    if selected is None:
        return None
    return selected["full_name"]

# Pull a model, reporting the outcome
def pull_and_report(model_name):
    logger.log_info("Pulling %s ..." % model_name)
    if pull_model(model_name):
        logger.log_info("Successfully pulled %s" % model_name)
        return True
    logger.log_error("Failed to pull %s" % model_name)
    return False

# Pull a model in a quantization chosen from those available
# Declining the choice pulls nothing and is not a failure.
def pull_with_quantization(model_name):
    chosen = choose_quantization(model_name)
    if chosen is None:
        return True
    return pull_and_report(chosen)

# List installed models
def action_list(model_name = None, purpose = None, harness = None, show_all = False):
    if not ensure_running():
        return False
    models = list_installed_models()
    if not models:
        logger.log_info("No models installed")
        return True
    logger.log_info("Installed models:")
    logger.log_info("-" * 60)
    for model in models:
        logger.log_info("  %s" % format_installed_model_display(model))
    logger.log_info("-" * 60)
    logger.log_info("Total: %d models" % len(models))
    return True

# Show available models with recommendations
def action_available(model_name = None, purpose = None, harness = None, show_all = False):
    hw = get_server_hardware()
    hardware.print_hardware_summary(hw)
    logger.log_info("")

    # Determine purpose filter
    if not purpose:
        purpose_options = [{"key": p, "label": "%s - %s" % (p, PURPOSE_DESCRIPTIONS[p])} for p in ALL_PURPOSES]
        purpose_options.insert(0, {"key": None, "label": "All purposes"})
        selected = prompts.prompt_for_selection(
            "Select a purpose:",
            purpose_options,
            display_func = lambda x: x["label"]
        )
        if selected is None:
            return True
        purpose = selected["key"]

    # Get recommendations
    vram_mb = hw["gpu_vram_total_mb"]
    ram_mb = hw["system_ram_mb"]

    # Include unfit + cloud so we can categorize and count them here
    models = get_recommended_models(
        purpose = purpose, vram_mb = vram_mb, ram_mb = ram_mb,
        include_unfit = True, include_cloud = True)
    if not models:
        logger.log_info("No models found for the selected criteria")
        return True

    # Categorize models
    gpu_models = [m for m in models if m["fit"] == FIT_GPU]
    offload_models = [m for m in models if m["fit"] == FIT_OFFLOAD]
    cloud_models = [m for m in models if m["fit"] == FIT_CLOUD]
    no_fit_models = [m for m in models if m["fit"] == FIT_NONE]

    # Filter display unless show_all
    if not show_all:
        display_models = gpu_models + offload_models + cloud_models
    else:
        display_models = models

    # Check what's already installed
    installed_names = set()
    if is_running():
        installed_names = {m["name"] for m in list_installed_models()}

    # Display
    logger.log_info("")
    purpose_label = purpose if purpose else "all purposes"
    vram_free = hw["gpu_vram_free_mb"]
    logger.log_info("Available models for %s (VRAM: %d MB total, %d MB free, RAM: %d MB):" % (purpose_label, vram_mb, vram_free, ram_mb))
    logger.log_info("[+] fits GPU  [~] CPU offload (slower)  [C] cloud-hosted  [-] too large  [*] installed")
    logger.log_info("-" * 70)
    for model in display_models:
        if model["name"] in installed_names:
            prefix = "*"
        elif model["fit"] == FIT_GPU:
            prefix = "+"
        elif model["fit"] == FIT_OFFLOAD:
            prefix = "~"
        elif model["fit"] == FIT_CLOUD:
            prefix = "C"
        else:
            prefix = "-"
        if model["fit"] == FIT_CLOUD:
            logger.log_info("  [%s] %s (cloud-hosted)" % (prefix, model["display"]))
        else:
            vram_gb = model["vram_mb"] / 1024
            speed_note = " (CPU offload, slower)" if model["fit"] == FIT_OFFLOAD else ""
            logger.log_info("  [%s] %s (%s, ~%.1f GB)%s" % (prefix, model["display"], model["params"], vram_gb, speed_note))
        logger.log_info("      %s" % model["description"])
        if model["fit"] != FIT_CLOUD:
            logger.log_info("      ollama pull %s" % model["name"])
    logger.log_info("-" * 70)
    logger.log_info("%d fit GPU, %d with CPU offload, %d cloud, %d too large" % (len(gpu_models), len(offload_models), len(cloud_models), len(no_fit_models)))
    if not show_all and no_fit_models:
        logger.log_info("Use --all to see models that exceed your system")

    # Offer to pull (GPU + offload models are pullable; cloud/too-large are not)
    pullable = [m for m in display_models if m["name"] not in installed_names and m["fit"] not in (FIT_NONE, FIT_CLOUD)]
    if pullable:
        logger.log_info("")
        if prompts.prompt_for_confirmation("Would you like to pull a model?", default_yes = False):
            selected = prompts.prompt_for_selection(
                "Select a model to pull:",
                pullable,
                display_func = lambda m: "%s (%s, ~%.1f GB)" % (m["display"], m["params"], m["vram_mb"] / 1024)
            )
            if selected:
                if not pull_with_quantization(selected["name"]):
                    return False
    return True

# Pull a model
def action_pull(model_name = None, purpose = None, harness = None, show_all = False):
    if not ensure_running():
        return False
    if not model_name:
        return action_available(purpose = purpose, show_all = show_all)
    return pull_with_quantization(model_name)

# Delete a model
def action_delete(model_name = None, purpose = None, harness = None, show_all = False):
    if not ensure_running():
        return False
    if not model_name:

        # Let user select from installed models
        models = list_installed_models()
        if not models:
            logger.log_info("No models installed")
            return True
        selected = prompts.prompt_for_selection(
            "Select a model to delete:",
            models,
            display_func = format_installed_model_display
        )
        if selected is None:
            return True
        model_name = selected["name"]

    # Let user delete model
    if prompts.prompt_for_confirmation("Delete model '%s'?" % model_name, default_yes = False):
        logger.log_info("Deleting %s ..." % model_name)
        if delete_model(model_name):
            logger.log_info("Successfully deleted %s" % model_name)
            return True
        else:
            logger.log_error("Failed to delete %s" % model_name)
            return False
    return True

# Show model info
def action_info(model_name = None, purpose = None, harness = None, show_all = False):
    if not ensure_running():
        return False
    if not model_name:
        models = list_installed_models()
        if not models:
            logger.log_info("No models installed")
            return True
        selected = prompts.prompt_for_selection(
            "Select a model:",
            models,
            display_func = format_installed_model_display
        )
        if selected is None:
            return True
        model_name = selected["name"]
    info = show_model(model_name)
    if info:
        logger.log_info("Model info for %s:" % model_name)
        print(info)
        return True
    else:
        logger.log_error("Could not get info for %s (is it installed?)" % model_name)
        return False

# Launch a coding-agent harness with an Ollama model as the backend
def action_harness(model_name = None, purpose = None, harness = None, show_all = False):
    if not ensure_running():
        return False

    # Resolve the harness
    harness = harness or DEFAULT_HARNESS
    if harness not in HARNESSES:
        logger.log_error("Unknown harness '%s'. Available: %s" % (harness, ", ".join(get_harness_keys())))
        return False
    harness_name = HARNESSES[harness]["name"]

    # Get installed models
    models = list_installed_models()
    if not models:
        logger.log_info("No models installed. Run 'ollama_tool available' to find models.")
        return False
    installed_names = {m["name"] for m in models}
    if not model_name:

        # Let user select from installed models
        selected = prompts.prompt_for_selection(
            "Select a model for %s:" % harness_name,
            models,
            display_func = format_installed_model_display
        )
        if selected is None:
            return True
        model_name = selected["name"]
    elif model_name not in installed_names:
        logger.log_error("Model '%s' is not installed" % model_name)
        logger.log_info("Installed models: %s" % ", ".join(sorted(installed_names)))
        if not prompts.prompt_for_confirmation("Pull '%s' now?" % model_name, default_yes = True):
            return False
        chosen = choose_quantization(model_name, chat_only = True)
        if chosen is None:
            return True
        if not pull_and_report(chosen):
            return False
        model_name = chosen

    # Warn if the model's context window is too small for this harness
    if not check_context_window(model_name, harness):
        if not prompts.prompt_for_confirmation("Launch anyway?", default_yes = False):
            return True

    # Launch the harness against the model
    logger.log_info("Launching %s with model: %s" % (harness_name, model_name))
    return launch_harness(model_name, harness)

# Recommend the best model for the current hardware and purpose
def action_best(model_name = None, purpose = None, harness = None, show_all = False):
    hw = get_server_hardware()
    purpose = purpose or PURPOSE_TOOLS
    best = get_best_model(
        purpose = purpose,
        vram_mb = hw["gpu_vram_total_mb"],
        ram_mb = hw["system_ram_mb"])
    if not best:
        logger.log_info("No model fits this hardware for purpose '%s'." % purpose)
        logger.log_info("Run 'ollama_tool available -p %s --all' to see everything." % purpose)
        return True
    fit_note = "fits GPU" if best["fit"] == FIT_GPU else "CPU offload (slower)"
    logger.log_info("Best model for %s: %s (%s, ~%.1f GB, %s)" % (
        purpose, best["display"], best["params"], best["vram_mb"] / 1024, fit_note))
    logger.log_info("  %s" % best["description"])
    installed_names = set()
    if is_running():
        installed_names = {m["name"] for m in list_installed_models()}
    if best["name"] in installed_names:
        logger.log_info("Already installed.")
        return True
    if prompts.prompt_for_confirmation("Pull '%s' now?" % best["name"], default_yes = False):
        return pull_with_quantization(best["name"])
    return True

# Action dispatch
# Start a coding agent on the best coding model for the server
# The one command to reach for: it picks, pulls and sizes the model, then runs
# the agent in the current directory.
def action_code(model_name = None, purpose = None, harness = None, show_all = False):
    harness = harness or DEFAULT_HARNESS
    if harness not in HARNESSES:
        logger.log_error("Unknown harness '%s'. Available: %s" % (harness, ", ".join(get_harness_keys())))
        return False
    spec = HARNESSES[harness]
    context_tokens = max(spec.get("coding_context", CODING_CONTEXT_TOKENS), spec["min_tokens"])
    if model_name:
        if not ensure_running():
            return False
        variant = prepare_coding_variant(model_name, context_tokens)
    else:
        variant = prepare_coding_model(context_tokens)
    if not variant:
        return False
    logger.log_info("Launching %s with model: %s" % (HARNESSES[harness]["name"], variant))
    return launch_harness(variant, harness)

# Command that installs or updates ollama, run on the server
# It was installed from its own script rather than a package, so the system's
# automatic updates never touch it. The installer replaces the binary and its
# unit file; the drop-in that sets how it runs is left alone.
OLLAMA_INSTALL_COMMAND = "curl -fsSL https://ollama.com/install.sh | sh"

# Get the server's ollama version, or None when it is not answering
def get_server_version():
    return (network.get_remote_json(get_api_base() + "/api/version") or {}).get("version")

# Update ollama on the server by rerunning its installer there over SSH
def action_update(model_name = None, purpose = None, harness = None, show_all = False):
    host = get_ssh_host()
    if not host:
        logger.log_error("Updating needs the server's SSH destination in [Tools.Ollama] ollama_ssh_host")
        return False
    before = get_server_version()
    logger.log_info("Updating ollama on %s (now %s)" % (host, before or "not answering"))
    if command.run_returncode_command(["ssh", host, OLLAMA_INSTALL_COMMAND]) != 0:
        logger.log_error("The ollama installer failed on %s" % host)
        return False
    for _ in range(30):
        after = get_server_version()
        if after:
            logger.log_info("ollama on %s is at %s" % (host, after))
            return True
        runtime.sleep_program(1)
    logger.log_error("ollama on %s did not come back after updating" % host)
    return False

ACTIONS = {
    "list": action_list,
    "available": action_available,
    "best": action_best,
    "pull": action_pull,
    "delete": action_delete,
    "info": action_info,
    "harness": action_harness,
    "code": action_code,
    "update": action_update,
}

# Get the available action names
def get_action_keys():
    return list(ACTIONS.keys())

# Run an action by name
def run_action(action, model_name = None, purpose = None, harness = None, show_all = False):
    if action not in ACTIONS:
        logger.log_error("Unknown action '%s'. Valid actions: %s" % (action, ", ".join(get_action_keys())))
        return False
    return ACTIONS[action](
        model_name = model_name,
        purpose = purpose,
        harness = harness,
        show_all = show_all)
