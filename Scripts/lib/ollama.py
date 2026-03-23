# Imports
import re

# Local imports
import command
import logger
import network
import hardware
import system

###########################################################
# Ollama API
###########################################################

# Default Ollama API base URL
OLLAMA_API_BASE = "http://localhost:11434"

# Check if Ollama is running
def is_running():
    return network.is_url_reachable(OLLAMA_API_BASE)

# Start Ollama serve in the background
def start_serve():
    if is_running():
        return True
    logger.log_info("Starting Ollama server...")
    options = command.create_command_options()
    options.set_is_daemon(True)
    command.run_returncode_command(["ollama", "serve"], options = options)
    for _ in range(10):
        system.sleep_program(1)
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
    result = network.get_remote_json(OLLAMA_API_BASE + "/api/tags")
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

# Pull (download) a model
def pull_model(model_name):
    code = command.run_returncode_command(
        ["ollama", "pull", model_name])
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

# Parse model entries from Ollama search HTML
def parse_search_html(html):
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

        # Determine primary purpose from capabilities
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
            # Cloud or no-size models
            models.append({
                "name": base_name,
                "display": base_name,
                "purpose": purpose,
                "params": "?",
                "vram_mb": 0,
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
        return parse_search_html(html)
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
# Claude Code integration
###########################################################

# Minimum context window recommended for Claude Code
CLAUDE_CODE_MIN_CONTEXT = 64000

# Launch Claude Code with an Ollama model
def launch_claude_code(model_name):
    options = command.create_command_options()
    options.set_env_var("ANTHROPIC_AUTH_TOKEN", "")
    options.set_env_var("ANTHROPIC_API_KEY", "ollama")
    options.set_env_var("ANTHROPIC_BASE_URL", OLLAMA_API_BASE)
    options.set_passthrough(True)
    code = command.run_returncode_command(
        ["claude", "--model", model_name, "--bare"],
        options = options)
    return code == 0

###########################################################
# Recommendation logic
###########################################################

# Fit categories
FIT_GPU = "gpu"           # Fits entirely in VRAM
FIT_OFFLOAD = "offload"   # Exceeds VRAM but fits in system RAM (CPU offload)
FIT_NONE = "none"         # Exceeds both VRAM and RAM

# Get models with fit classification based on VRAM and RAM
def get_recommended_models(purpose = None, vram_mb = None, ram_mb = None):
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
        if model["vram_mb"] <= 0:
            model_entry["fit"] = FIT_NONE
        elif vram_mb > 0 and model["vram_mb"] <= vram_mb:
            model_entry["fit"] = FIT_GPU
        elif ram_mb > 0 and model["vram_mb"] <= ram_mb:
            model_entry["fit"] = FIT_OFFLOAD
        else:
            model_entry["fit"] = FIT_NONE
        model_entry["fits_vram"] = model_entry["fit"] != FIT_NONE
        models.append(model_entry)
    return models

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
