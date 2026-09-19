# Imports
import re
import shutil

# Local imports
import joybox.command as command
import joybox.logger as logger
import joybox.network as network
import joybox.hardware as hardware
import joybox.prompts as prompts
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

# Start Ollama serve in the background
def start_serve():
    if is_running():
        return True
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
    options = command.create_command_options()
    options.set_passthrough(True)
    code = command.run_returncode_command(
        ["ollama", "pull", model_name],
        options = options)
    return code == 0

# Delete a model
def delete_model(model_name):
    code = command.run_returncode_command(
        ["ollama", "rm", model_name])
    return code == 0

# Show model info
def show_model(model_name):
    output = command.run_output_command(
        ["ollama", "show", model_name])
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

# Parse size string like "5.2GB", "890MB" to MB
def parse_size_to_mb(size_str):
    size_str = size_str.strip().upper()
    match = re.match(r'^([\d.]+)\s*(GB|MB|KB|TB)$', size_str)
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2)
    if unit == "TB":
        return int(value * 1024 * 1024)
    if unit == "GB":
        return int(value * 1024)
    if unit == "MB":
        return int(value)
    if unit == "KB":
        return max(1, int(value / 1024))
    return 0

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
    model_family = parts[0]
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

# Coding-agent harnesses that can run against a local Ollama model. Each entry
# defines the client's display name, its recommended minimum context window (for
# check_context_window), the command to launch it, and the environment that
# points it at the Ollama server. In command/env, "{model}" is replaced with the
# model name and "{api_base}" with the configured Ollama base URL.
#
# Backends: claude_code talks to Ollama's Anthropic-compatible endpoint;
# codex/opencode use Ollama's OpenAI-compatible /v1 endpoint. The OpenAI-
# compatible entries are best-effort — those tools may also need their own
# provider config, and their exact launch flags vary by version.
HARNESSES = {
    "claude_code": {
        "name": "Claude Code",
        "min_tokens": 64000,
        "command": ["claude", "--model", "{model}", "--bare"],
        "env": {
            "ANTHROPIC_BASE_URL": "{api_base}",
            "ANTHROPIC_API_KEY": "ollama",
            "ANTHROPIC_AUTH_TOKEN": "",
        },
        "install_hint": "https://docs.claude.com/claude-code",
    },
    "codex": {
        "name": "Codex CLI",
        "min_tokens": 8000,
        "command": ["codex", "-m", "{model}"],
        "env": {"OPENAI_BASE_URL": "{api_base}/v1", "OPENAI_API_KEY": "ollama"},
        "install_hint": "https://github.com/openai/codex",
    },
    "opencode": {
        "name": "OpenCode",
        "min_tokens": 8000,
        "command": ["opencode", "--model", "{model}"],
        "env": {"OPENAI_BASE_URL": "{api_base}/v1", "OPENAI_API_KEY": "ollama"},
        "install_hint": "https://opencode.ai",
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
    def fill(value):
        return value.replace("{api_base}", api_base).replace("{model}", model_name)
    cmd = [fill(part) for part in spec["command"]]

    # Require the harness binary to be installed
    if not shutil.which(cmd[0]):
        logger.log_error("%s is not installed (command '%s' not found)" % (spec["name"], cmd[0]))
        if spec.get("install_hint"):
            logger.log_info("Install: %s" % spec["install_hint"])
        return False

    options = command.create_command_options()
    for key, value in spec.get("env", {}).items():
        options.set_env_var(key, fill(value))
    options.set_passthrough(True)
    return command.run_returncode_command(cmd, options = options) == 0

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
    if vram_mb is None:
        vram_mb = hardware.get_gpu_vram_total_mb()
    if ram_mb is None:
        ram_mb = hardware.get_system_ram_mb()
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
def pull_with_quantization(model_name):
    hw = hardware.get_hardware_summary()
    vram_mb = hw["gpu_vram_total_mb"]
    ram_mb = hw["system_ram_mb"]

    # Check for available quantizations
    options = get_quantization_options(model_name)
    if options and len(options) > 1:
        logger.log_info("Available quantizations for %s:" % model_name)
        logger.log_info("[+] fits GPU  [~] CPU offload  [-] too large")
        selected = prompts.prompt_for_selection(
            "Select quantization:",
            options,
            display_func = lambda o: format_quantization_display(o, vram_mb, ram_mb)
        )
        if selected is None:
            return True
        model_name = selected["full_name"]

    # Pull model
    logger.log_info("Pulling %s ..." % model_name)
    if pull_model(model_name):
        logger.log_info("Successfully pulled %s" % model_name)
        return True
    else:
        logger.log_error("Failed to pull %s" % model_name)
        return False

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
    hw = hardware.get_hardware_summary()
    hardware.print_hardware_summary()
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
        if prompts.prompt_for_confirmation("Pull '%s' now?" % model_name, default_yes = True):
            if not pull_with_quantization(model_name):
                return False
        else:
            return False

    # Warn if the model's context window is too small for this harness
    if not check_context_window(model_name, harness):
        if not prompts.prompt_for_confirmation("Launch anyway?", default_yes = False):
            return True

    # Launch the harness against the model
    logger.log_info("Launching %s with model: %s" % (harness_name, model_name))
    return launch_harness(model_name, harness)

# Recommend the best model for the current hardware and purpose
def action_best(model_name = None, purpose = None, harness = None, show_all = False):
    hw = hardware.get_hardware_summary()
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
ACTIONS = {
    "list": action_list,
    "available": action_available,
    "best": action_best,
    "pull": action_pull,
    "delete": action_delete,
    "info": action_info,
    "harness": action_harness,
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
