# The ollama tool's actions, each run by name from the command line.

# Imports
import re

# Local imports
from joybox import command
from joybox import dispatch
from joybox import hardware
from joybox import logger
from joybox import network
from joybox import ollama
from joybox import ollamaagents
from joybox import ollamacatalog
from joybox import prompts
from joybox import runtime
from joybox import terminal

###########################################################
# Actions
#
# Each action names only the options it reads; run_action offers them all and
# passes each action the ones it names.
###########################################################

# Whether a tag is a base or text model, which continues text rather than follows a
# conversation, so cannot drive a chat or call tools
def is_completion_only_tag(tag):
    return re.search(r"(^|-)(base|text)(-|$)", tag.lower()) is not None

# Choose which quantization of a model to pull
# Returns the full name chosen, the name itself when there is no choice to
# make, or None when the choice is declined.
def choose_quantization(model_name, chat_only = False):
    options = ollamacatalog.get_quantization_options(model_name)
    if chat_only:
        options = [o for o in options if not is_completion_only_tag(o["tag"])]
    if len(options) <= 1:
        return options[0]["full_name"] if options else model_name
    hw = ollama.get_server_hardware()
    logger.log_info("Available quantizations for %s:" % model_name)
    logger.log_info("[+] fits GPU  [~] CPU offload  [-] too large")
    selected = prompts.prompt_for_selection(
        "Select quantization:",
        options,
        display_func = lambda o: ollamacatalog.format_quantization_display(o, hw["gpu_vram_total_mb"], hw["system_ram_mb"])
    )
    if selected is None:
        return None
    return selected["full_name"]

# Pull a model, reporting the outcome
def pull_and_report(model_name):
    logger.log_info("Pulling %s ..." % model_name)
    if ollama.pull_model(model_name):
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
def action_list():
    if not ollama.ensure_running():
        return False
    models = ollama.list_installed_models()
    if not models:
        logger.log_info("No models installed")
        return True
    logger.log_info("Installed models:")
    logger.log_info("-" * 60)
    for model in models:
        logger.log_info("  %s" % ollamacatalog.format_installed_model_display(model))
    logger.log_info("-" * 60)
    logger.log_info("Total: %d models" % len(models))
    return True

# Show available models with recommendations
def action_available(purpose = None, show_all = False):
    hw = ollama.get_server_hardware()
    hardware.print_hardware_summary(hw)
    logger.log_info("")

    # Determine purpose filter
    if not purpose:
        purpose_options = [{"key": p, "label": "%s - %s" % (p, ollamacatalog.PURPOSE_DESCRIPTIONS[p])} for p in ollamacatalog.ALL_PURPOSES]
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
    models = ollamacatalog.get_recommended_models(
        purpose = purpose, vram_mb = vram_mb, ram_mb = ram_mb,
        include_unfit = True, include_cloud = True)
    if not models:
        logger.log_info("No models found for the selected criteria")
        return True

    # Categorize models
    gpu_models = [m for m in models if m["fit"] == ollamacatalog.FIT_GPU]
    offload_models = [m for m in models if m["fit"] == ollamacatalog.FIT_OFFLOAD]
    cloud_models = [m for m in models if m["fit"] == ollamacatalog.FIT_CLOUD]
    no_fit_models = [m for m in models if m["fit"] == ollamacatalog.FIT_NONE]

    # Filter display unless show_all
    if not show_all:
        display_models = gpu_models + offload_models + cloud_models
    else:
        display_models = models

    # Check what's already installed
    installed_names = set()
    if ollama.is_running():
        installed_names = {m["name"] for m in ollama.list_installed_models()}

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
        elif model["fit"] == ollamacatalog.FIT_GPU:
            prefix = "+"
        elif model["fit"] == ollamacatalog.FIT_OFFLOAD:
            prefix = "~"
        elif model["fit"] == ollamacatalog.FIT_CLOUD:
            prefix = "C"
        else:
            prefix = "-"
        if model["fit"] == ollamacatalog.FIT_CLOUD:
            logger.log_info("  [%s] %s (cloud-hosted)" % (prefix, model["display"]))
        else:
            vram_gb = model["vram_mb"] / 1024
            speed_note = " (CPU offload, slower)" if model["fit"] == ollamacatalog.FIT_OFFLOAD else ""
            logger.log_info("  [%s] %s (%s, ~%.1f GB)%s" % (prefix, model["display"], model["params"], vram_gb, speed_note))
        logger.log_info("      %s" % model["description"])
        if model["fit"] != ollamacatalog.FIT_CLOUD:
            logger.log_info("      ollama pull %s" % model["name"])
    logger.log_info("-" * 70)
    logger.log_info("%d fit GPU, %d with CPU offload, %d cloud, %d too large" % (len(gpu_models), len(offload_models), len(cloud_models), len(no_fit_models)))
    if not show_all and no_fit_models:
        logger.log_info("Use --all to see models that exceed your system")

    # Offer to pull (GPU + offload models are pullable; cloud/too-large are not)
    pullable = [m for m in display_models if m["name"] not in installed_names and m["fit"] not in (ollamacatalog.FIT_NONE, ollamacatalog.FIT_CLOUD)]
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
def action_pull(model_name = None, purpose = None, show_all = False):
    if not ollama.ensure_running():
        return False
    if not model_name:
        return action_available(purpose = purpose, show_all = show_all)
    return pull_with_quantization(model_name)

# Delete a model
def action_delete(model_name = None):
    if not ollama.ensure_running():
        return False
    if not model_name:

        # Let user select from installed models
        models = ollama.list_installed_models()
        if not models:
            logger.log_info("No models installed")
            return True
        selected = prompts.prompt_for_selection(
            "Select a model to delete:",
            models,
            display_func = ollamacatalog.format_installed_model_display
        )
        if selected is None:
            return True
        model_name = selected["name"]

    # Let user delete model
    if prompts.prompt_for_confirmation("Delete model '%s'?" % model_name, default_yes = False):
        logger.log_info("Deleting %s ..." % model_name)
        if ollama.delete_model(model_name):
            logger.log_info("Successfully deleted %s" % model_name)
            return True
        logger.log_error("Failed to delete %s" % model_name)
        return False
    return True

# Show model info
def action_info(model_name = None):
    if not ollama.ensure_running():
        return False
    if not model_name:
        models = ollama.list_installed_models()
        if not models:
            logger.log_info("No models installed")
            return True
        selected = prompts.prompt_for_selection(
            "Select a model:",
            models,
            display_func = ollamacatalog.format_installed_model_display
        )
        if selected is None:
            return True
        model_name = selected["name"]
    info = ollama.show_model(model_name)
    if info:
        logger.log_info("Model info for %s:" % model_name)
        terminal.write(info + "\n")
        return True
    logger.log_error("Could not get info for %s (is it installed?)" % model_name)
    return False

# Launch a coding-agent harness with an Ollama model as the backend
def action_harness(model_name = None, harness = None):
    if not ollama.ensure_running():
        return False

    # Resolve the harness
    harness = harness or ollamaagents.DEFAULT_HARNESS
    if harness not in ollamaagents.HARNESSES:
        logger.log_error("Unknown harness '%s'. Available: %s" % (harness, ", ".join(ollamaagents.get_harness_keys())))
        return False
    harness_name = ollamaagents.HARNESSES[harness]["name"]

    # Get installed models
    models = ollama.list_installed_models()
    if not models:
        logger.log_info("No models installed. Run 'ollama_tool available' to find models.")
        return False
    installed_names = {m["name"] for m in models}
    if not model_name:

        # Let user select from installed models
        selected = prompts.prompt_for_selection(
            "Select a model for %s:" % harness_name,
            models,
            display_func = ollamacatalog.format_installed_model_display
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
    if not ollamaagents.check_context_window(model_name, harness):
        if not prompts.prompt_for_confirmation("Launch anyway?", default_yes = False):
            return True

    # Launch the harness against the model
    logger.log_info("Launching %s with model: %s" % (harness_name, model_name))
    return ollamaagents.launch_harness(model_name, harness)

# Recommend the best model for the current hardware and purpose
def action_best(purpose = None):
    hw = ollama.get_server_hardware()
    purpose = purpose or ollamacatalog.PURPOSE_TOOLS
    best = ollamacatalog.get_best_model(
        purpose = purpose,
        vram_mb = hw["gpu_vram_total_mb"],
        ram_mb = hw["system_ram_mb"])
    if not best:
        logger.log_info("No model fits this hardware for purpose '%s'." % purpose)
        logger.log_info("Run 'ollama_tool available -p %s --all' to see everything." % purpose)
        return True
    fit_note = "fits GPU" if best["fit"] == ollamacatalog.FIT_GPU else "CPU offload (slower)"
    logger.log_info("Best model for %s: %s (%s, ~%.1f GB, %s)" % (
        purpose, best["display"], best["params"], best["vram_mb"] / 1024, fit_note))
    logger.log_info("  %s" % best["description"])
    installed_names = set()
    if ollama.is_running():
        installed_names = {m["name"] for m in ollama.list_installed_models()}
    if best["name"] in installed_names:
        logger.log_info("Already installed.")
        return True
    if prompts.prompt_for_confirmation("Pull '%s' now?" % best["name"], default_yes = False):
        return pull_with_quantization(best["name"])
    return True

# Start a coding agent in the current directory on the best coding model for the
# server, picking, pulling and sizing it first
def action_code(model_name = None, harness = None):
    harness = harness or ollamaagents.DEFAULT_HARNESS
    if harness not in ollamaagents.HARNESSES:
        logger.log_error("Unknown harness '%s'. Available: %s" % (harness, ", ".join(ollamaagents.get_harness_keys())))
        return False
    spec = ollamaagents.HARNESSES[harness]
    context_tokens = max(spec.get("coding_context", ollamaagents.CODING_CONTEXT_TOKENS), spec["min_tokens"])
    if model_name:
        if not ollama.ensure_running():
            return False
        variant = ollamaagents.prepare_coding_variant(model_name, context_tokens)
    else:
        variant = ollamaagents.prepare_coding_model(context_tokens)
    if not variant:
        return False
    logger.log_info("Launching %s with model: %s" % (ollamaagents.HARNESSES[harness]["name"], variant))
    return ollamaagents.launch_harness(variant, harness)

# Command that installs or updates ollama, run on the server
# It was installed from its own script rather than a package, so the system's
# automatic updates never touch it. The installer replaces the binary and its
# unit file; the drop-in that sets how it runs is left alone.
OLLAMA_INSTALL_COMMAND = "curl -fsSL https://ollama.com/install.sh | sh"

# Get the server's ollama version, or None when it is not answering
def get_server_version():
    return (network.get_remote_json(ollama.get_api_base() + "/api/version") or {}).get("version")

# Update ollama on the server by rerunning its installer there over SSH
def action_update():
    host = ollama.get_ssh_host()
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

# Action dispatch
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
    return dispatch.call_with_options(
        ACTIONS[action],
        model_name = model_name,
        purpose = purpose,
        harness = harness,
        show_all = show_all)
