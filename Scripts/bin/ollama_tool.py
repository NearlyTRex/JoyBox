#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts
import joybox.hardware as hardware
import joybox.ollama as ollama

# Parse arguments
parser = arguments.ArgumentParser(description = "Manage Ollama models based on your system hardware.")
parser.add_string_argument(
    args = ("action",),
    description = "Action to perform: list, available, best, pull, delete, info, harness")
parser.add_string_argument(
    args = ("-p", "--purpose"),
    description = "Filter by purpose: chat, tools, reasoning, vision, embedding, cloud")
parser.add_string_argument(
    args = ("-m", "--model"),
    description = "Model name for pull/delete/info/harness actions")
parser.add_string_argument(
    args = ("-H", "--harness"),
    default = None,
    description = "Coding-agent harness for the 'harness' action: claude_code, aider, codex, opencode (default: claude_code)")
parser.add_boolean_argument(
    args = ("--all",),
    description = "Show all models including those that exceed VRAM")
args, unknown = parser.parse_known_args()

# Pull a model with quantization selection
def pull_with_quantization(model_name):
    hw = hardware.get_hardware_summary()
    vram_mb = hw["gpu_vram_total_mb"]
    ram_mb = hw["system_ram_mb"]

    # Check for available quantizations
    options = ollama.get_quantization_options(model_name)
    if options and len(options) > 1:
        logger.log_info("Available quantizations for %s:" % model_name)
        logger.log_info("[+] fits GPU  [~] CPU offload  [-] too large")
        selected = prompts.prompt_for_selection(
            "Select quantization:",
            options,
            display_func = lambda o: ollama.format_quantization_display(o, vram_mb, ram_mb)
        )
        if selected is None:
            return True
        model_name = selected["full_name"]

    # Pull model
    logger.log_info("Pulling %s ..." % model_name)
    if ollama.pull_model(model_name):
        logger.log_info("Successfully pulled %s" % model_name)
        return True
    else:
        logger.log_error("Failed to pull %s" % model_name)
        return False

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
        logger.log_info("  %s" % ollama.format_installed_model_display(model))
    logger.log_info("-" * 60)
    logger.log_info("Total: %d models" % len(models))
    return True

# Show available models with recommendations
def action_available():
    hw = hardware.get_hardware_summary()
    hardware.print_hardware_summary()
    logger.log_info("")

    # Determine purpose filter
    purpose = args.purpose
    if not purpose:
        purpose_options = [{"key": p, "label": "%s - %s" % (p, ollama.PURPOSE_DESCRIPTIONS[p])} for p in ollama.ALL_PURPOSES]
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
    models = ollama.get_recommended_models(
        purpose = purpose, vram_mb = vram_mb, ram_mb = ram_mb,
        include_unfit = True, include_cloud = True)
    if not models:
        logger.log_info("No models found for the selected criteria")
        return True

    # Categorize models
    gpu_models = [m for m in models if m["fit"] == ollama.FIT_GPU]
    offload_models = [m for m in models if m["fit"] == ollama.FIT_OFFLOAD]
    cloud_models = [m for m in models if m["fit"] == ollama.FIT_CLOUD]
    no_fit_models = [m for m in models if m["fit"] == ollama.FIT_NONE]

    # Filter display unless --all
    show_all = args.all if hasattr(args, "all") else False
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
        elif model["fit"] == ollama.FIT_GPU:
            prefix = "+"
        elif model["fit"] == ollama.FIT_OFFLOAD:
            prefix = "~"
        elif model["fit"] == ollama.FIT_CLOUD:
            prefix = "C"
        else:
            prefix = "-"
        if model["fit"] == ollama.FIT_CLOUD:
            logger.log_info("  [%s] %s (cloud-hosted)" % (prefix, model["display"]))
        else:
            vram_gb = model["vram_mb"] / 1024
            speed_note = " (CPU offload, slower)" if model["fit"] == ollama.FIT_OFFLOAD else ""
            logger.log_info("  [%s] %s (%s, ~%.1f GB)%s" % (prefix, model["display"], model["params"], vram_gb, speed_note))
        logger.log_info("      %s" % model["description"])
        if model["fit"] != ollama.FIT_CLOUD:
            logger.log_info("      ollama pull %s" % model["name"])
    logger.log_info("-" * 70)
    logger.log_info("%d fit GPU, %d with CPU offload, %d cloud, %d too large" % (len(gpu_models), len(offload_models), len(cloud_models), len(no_fit_models)))
    if not show_all and no_fit_models:
        logger.log_info("Use --all to see models that exceed your system")

    # Offer to pull (GPU + offload models are pullable; cloud/too-large are not)
    pullable = [m for m in display_models if m["name"] not in installed_names and m["fit"] not in (ollama.FIT_NONE, ollama.FIT_CLOUD)]
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
def action_pull():
    if not ollama.ensure_running():
        return False
    model_name = args.model
    if not model_name:
        return action_available()
    return pull_with_quantization(model_name)

# Delete a model
def action_delete():
    if not ollama.ensure_running():
        return False
    model_name = args.model
    if not model_name:

        # Let user select from installed models
        models = ollama.list_installed_models()
        if not models:
            logger.log_info("No models installed")
            return True
        selected = prompts.prompt_for_selection(
            "Select a model to delete:",
            models,
            display_func = ollama.format_installed_model_display
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
        else:
            logger.log_error("Failed to delete %s" % model_name)
            return False
    return True

# Show model info
def action_info():
    if not ollama.ensure_running():
        return False
    model_name = args.model
    if not model_name:
        models = ollama.list_installed_models()
        if not models:
            logger.log_info("No models installed")
            return True
        selected = prompts.prompt_for_selection(
            "Select a model:",
            models,
            display_func = ollama.format_installed_model_display
        )
        if selected is None:
            return True
        model_name = selected["name"]
    info = ollama.show_model(model_name)
    if info:
        logger.log_info("Model info for %s:" % model_name)
        print(info)
        return True
    else:
        logger.log_error("Could not get info for %s (is it installed?)" % model_name)
        return False

# Launch a coding-agent harness with an Ollama model as the backend
def action_harness():
    if not ollama.ensure_running():
        return False

    # Resolve the harness
    harness = args.harness or ollama.DEFAULT_HARNESS
    if harness not in ollama.HARNESSES:
        logger.log_error("Unknown harness '%s'. Available: %s" % (harness, ", ".join(ollama.get_harness_keys())))
        return False
    harness_name = ollama.HARNESSES[harness]["name"]

    # Get installed models
    models = ollama.list_installed_models()
    if not models:
        logger.log_info("No models installed. Run 'ollama_tool available' to find models.")
        return False
    installed_names = {m["name"] for m in models}
    model_name = args.model
    if not model_name:

        # Let user select from installed models
        selected = prompts.prompt_for_selection(
            "Select a model for %s:" % harness_name,
            models,
            display_func = ollama.format_installed_model_display
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
    if not ollama.check_context_window(model_name, harness):
        if not prompts.prompt_for_confirmation("Launch anyway?", default_yes = False):
            return True

    # Launch the harness against the model
    logger.log_info("Launching %s with model: %s" % (harness_name, model_name))
    return ollama.launch_harness(model_name, harness)

# Recommend the best model for the current hardware and purpose
def action_best():
    hw = hardware.get_hardware_summary()
    purpose = args.purpose or ollama.PURPOSE_TOOLS
    best = ollama.get_best_model(
        purpose = purpose,
        vram_mb = hw["gpu_vram_total_mb"],
        ram_mb = hw["system_ram_mb"])
    if not best:
        logger.log_info("No model fits this hardware for purpose '%s'." % purpose)
        logger.log_info("Run 'ollama_tool available -p %s --all' to see everything." % purpose)
        return True
    fit_note = "fits GPU" if best["fit"] == ollama.FIT_GPU else "CPU offload (slower)"
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

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Validate action
    action = args.action
    if action not in ACTIONS:
        logger.log_error("Unknown action '%s'. Valid actions: %s" % (action, ", ".join(ACTIONS.keys())))
        return False

    # Run action
    return ACTIONS[action]()

# Start
if __name__ == "__main__":
    system.run_main(main)
