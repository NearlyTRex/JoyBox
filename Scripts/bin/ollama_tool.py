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
import joybox.ollama as ollama

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Find, pull and manage Ollama models sized to this machine, and run a coding agent on one.",
    details = (
        "Talks to the Ollama server at `[Tools.Ollama] ollama_api_base` in `~/JoyBox.ini`\n"
        "(`http://localhost:11434` by default) to list models and point harnesses at it, while\n"
        "pulling, deleting and showing a model run the local `ollama` command. If the server\n"
        "does not answer, the actions that need it start `ollama serve` in the background and\n"
        "wait up to ten seconds for it.\n"
        "\n"
        "It detects GPU VRAM and system RAM (NVIDIA through `nvidia-smi`, then AMD and Intel\n"
        "Arc through the Linux DRM sysfs files, then `rocm-smi`; the card with the most VRAM\n"
        "counts) and marks each catalog model by how it fits: `[+]` fits in VRAM, `[~]` fits\n"
        "only with CPU offload into RAM (slower), `[C]` cloud-hosted, `[-]` too large for\n"
        "both, `[*]` already installed. The catalog comes from the ollama.com search page,\n"
        "with a small built-in list as a fallback when that cannot be reached.\n"
        "\n"
        "Actions:\n"
        "\n"
        "- `list`: show the models installed on the server.\n"
        "- `available`: show catalog models with their fit, then offer to pull one. Prompts\n"
        "  for a purpose when `-p` is omitted.\n"
        "- `best`: pick the best local model for a purpose (`tools` when `-p` is omitted):\n"
        "  the best fit tier, then the most parameters. Offers to pull it.\n"
        "- `pull`: download `-m`. A base name such as `qwen2.5-coder:7b` lists its tags\n"
        "  (quantizations and variants) to choose from; a full tag pulls directly. Without\n"
        "  `-m` it behaves like `available`.\n"
        "- `delete`: remove an installed model after confirmation; prompts for one without `-m`.\n"
        "- `info`: print `ollama show` output for a model; prompts for one without `-m`.\n"
        "- `harness`: start a coding-agent CLI with an installed model as its backend. An\n"
        "  uninstalled `-m` is offered for pulling first.\n"
        "\n"
        "Harnesses: `claude_code` runs `claude --model <m> --bare` against Ollama's Anthropic\n"
        "endpoint (`ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY=ollama`) and wants a context window\n"
        "of at least 64K tokens. `codex` (`codex -m <m>`) and `opencode` (`opencode --model\n"
        "<m>`) use the OpenAI-compatible `/v1` endpoint (`OPENAI_BASE_URL`,\n"
        "`OPENAI_API_KEY=ollama`) and want at least 8K. When the model's advertised context is\n"
        "below that, you are warned and asked whether to launch anyway."),
    examples = [
        ("List installed models", "ollama_tool list"),
        ("Browse tool-capable models that fit this machine", "ollama_tool available -p tools"),
        ("Include models too large for this machine", "ollama_tool available -p reasoning --all"),
        ("Let the tool pick the best coding model", "ollama_tool best -p tools"),
        ("Pull a model, choosing the quantization", "ollama_tool pull -m qwen2.5-coder:7b"),
        ("Pull one exact tag without the picker", "ollama_tool pull -m qwen2.5-coder:7b-instruct-q4_K_M"),
        ("Run Claude Code on a local model", "ollama_tool harness -m qwen2.5-coder:7b"),
        ("Run Codex CLI on a local model", "ollama_tool harness -H codex -m qwen2.5-coder:7b"),
        ("Show details of an installed model", "ollama_tool info -m qwen2.5-coder:7b"),
        ("Delete a model", "ollama_tool delete -m qwen2.5-coder:7b"),
    ],
    notes = [
        "This command has no common options: `-p` is `--purpose`, not a dry run, and every action that changes something asks first.",
        "In the tag picker, enter the number of the variant, or `0` to cancel.",
        "The context size shown for a tag is the model's advertised maximum. Ollama's runtime context (`num_ctx`) defaults much lower; for long agent sessions start the server with a larger one, e.g. `OLLAMA_CONTEXT_LENGTH=65536 ollama serve`.",
        "The `codex` and `opencode` harnesses may need their own provider configuration, and their flags vary by version. The harness CLI must be on `PATH`; otherwise an install link is shown.",
        "Local models are much weaker at agentic tool use than hosted Claude.",
    ],
    see_also = ["llm_chat", "claude_tool"],
    section = "AI")
parser.add_string_argument(
    args = ("action",),
    description = "Action to perform: `list`, `available`, `best`, `pull`, `delete`, `info` or `harness`")
parser.add_string_argument(
    args = ("-p", "--purpose"),
    description = "Purpose to filter or pick for: `chat`, `tools`, `reasoning`, `vision`, `embedding` or `cloud`")
parser.add_string_argument(
    args = ("-m", "--model"),
    description = "Model for `pull`, `delete`, `info` and `harness`: a base name such as `qwen2.5-coder:7b` or a full tag; prompts for one when omitted")
parser.add_string_argument(
    args = ("-H", "--harness"),
    default = None,
    description = "Coding-agent CLI for the `harness` action: `claude_code`, `codex` or `opencode`; `claude_code` when omitted")
parser.add_boolean_argument(
    args = ("--all",),
    description = "In `available`, also list models too large for this machine's VRAM and RAM")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Run action
    return ollama.run_action(
        action = args.action,
        model_name = args.model,
        purpose = args.purpose,
        harness = args.harness,
        show_all = args.all)

# Start
if __name__ == "__main__":
    system.run_main(main)
