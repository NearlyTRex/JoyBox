# Imports
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.ollama as ollama

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Find, pull and manage Ollama models sized to this machine, and run a coding agent on one.",
        details = (
            "Talks to the Ollama server at `[Tools.Ollama] ollama_api_base` in `~/JoyBox.ini`\n"
            "(`http://localhost:11434` by default) to list models and point harnesses at it.\n"
            "Pulling, deleting and showing a model run the local `ollama` command with `OLLAMA_HOST`\n"
            "set to that server, so they act on a remote one too. If a local server does not\n"
            "answer, the actions that need it start `ollama serve` in the background and wait up\n"
            "to ten seconds for it; a remote one that does not answer is an error.\n"
            "\n"
            "It detects GPU VRAM and system RAM (NVIDIA through `nvidia-smi`, then AMD and Intel\n"
            "Arc through the Linux DRM sysfs files, then `rocm-smi`; the card with the most VRAM\n"
            "counts) and marks each catalog model by how it fits: `[+]` fits in VRAM, `[~]` fits\n"
            "only with CPU offload into RAM (slower), `[C]` cloud-hosted, `[-]` too large for\n"
            "both, `[*]` already installed. The catalog comes from the ollama.com search page,\n"
            "with a small built-in list as a fallback when that cannot be reached.\n"
            "\n"
            "Fits are judged against the machine the server runs on. A remote server cannot be\n"
            "measured from here, so set `[Tools.Ollama] ollama_gpu_vram_mb` (and optionally\n"
            "`ollama_system_ram_mb`) to its sizes in megabytes; without them it warns and uses\n"
            "this machine's.\n"
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
            "- `code`: the one command for coding. Picks the most capable coding model from a\n"
            "  ranked list whose weights, context and load overhead fit the server's VRAM (or\n"
            "  prepares `-m`), pulls it if needed, builds the context into a `-ctxNNk` variant\n"
            "  (64K for Claude Code, 32K for the other harnesses, leaving room for a stronger model),\n"
            "  loads it to check it sits wholly in VRAM, falling back to the next model if not, and\n"
            "  starts the harness (Claude Code unless `-H`) in the current directory. A prepared\n"
            "  variant is reused, so later runs start at once.\n"
            "\n"
            "Harnesses: `claude_code` runs `claude --model <m> --bare` against Ollama's Anthropic\n"
            "endpoint and wants a context window of at least 64K tokens. `codex` uses its own\n"
            "ollama provider (`codex --oss --local-provider ollama`, pointed at the server with\n"
            "`CODEX_OSS_BASE_URL`). `opencode` is given an ollama provider through\n"
            "`OPENCODE_CONFIG_CONTENT`, so nothing is written to its config. `aider` runs\n"
            "`aider --model ollama_chat/<m>` with `OLLAMA_API_BASE`, and for a `-ctxNNk` variant a\n"
            "model-settings file under the cache dir that fixes `num_ctx`: left to itself aider\n"
            "sizes it to each request, and ollama reloads the model whenever it changes. Those three want at least\n"
            "8K, and aider and opencode send far less with each request than the other two, which\n"
            "suits local models. A `-ctxNNk` variant's window is passed to the harness, so it\n"
            "compacts the conversation before the model runs out. When a model's advertised\n"
            "context is below a harness's minimum, you are warned and asked whether to launch\n"
            "anyway."),
        examples = [
            ("List installed models", "ollama_tool list"),
            ("Browse tool-capable models that fit this machine", "ollama_tool available -p tools"),
            ("Include models too large for this machine", "ollama_tool available -p reasoning --all"),
            ("Let the tool pick the best coding model", "ollama_tool best -p tools"),
            ("Pull a model, choosing the quantization", "ollama_tool pull -m qwen2.5-coder:7b"),
            ("Pull one exact tag without the picker", "ollama_tool pull -m qwen2.5-coder:7b-instruct-q4_K_M"),
            ("Start coding on the best model the server can hold", "ollama_tool code"),
            ("Run Claude Code on a local model", "ollama_tool harness -m qwen2.5-coder:7b"),
            ("Run Codex CLI on a local model", "ollama_tool harness -H codex -m qwen2.5-coder:7b"),
            ("Start coding with aider on the best model the server can hold", "ollama_tool code -H aider"),
            ("Show details of an installed model", "ollama_tool info -m qwen2.5-coder:7b"),
            ("Delete a model", "ollama_tool delete -m qwen2.5-coder:7b"),
        ],
        notes = [
            "This command has no common options: `-p` is `--purpose`, not a dry run, and every action that changes something asks first.",
            "In the tag picker, enter the number of the variant, or `0` to cancel.",
            "The context size shown for a tag is the model's advertised maximum. Ollama's runtime context (`num_ctx`) defaults much lower; for long agent sessions start the server with a larger one, e.g. `OLLAMA_CONTEXT_LENGTH=65536 ollama serve`.",
            "The harness CLI must be on `PATH`; otherwise how to install it is shown. aider pins its dependencies, so the bootstrap installs it in a venv of its own.",
            "Local models are much weaker at agentic tool use than hosted Claude.",
        ],
        see_also = ["llm_chat", "claude_tool"],
        section = "AI")
    parser.add_string_argument(
        args = ("action",),
        description = "Action to perform: `list`, `available`, `best`, `pull`, `delete`, `info`, `harness` or `code`")
    parser.add_string_argument(
        args = ("-p", "--purpose"),
        description = "Purpose to filter or pick for: `chat`, `tools`, `reasoning`, `vision`, `embedding` or `cloud`")
    parser.add_string_argument(
        args = ("-m", "--model"),
        description = "Model for `pull`, `delete`, `info`, `harness` and `code`: a base name such as `qwen2.5-coder:7b` or a full tag; prompts for one when omitted")
    parser.add_string_argument(
        args = ("-H", "--harness"),
        default = None,
        description = "Coding-agent CLI for the `harness` and `code` actions: `claude_code`, `codex`, `opencode` or `aider`; `claude_code` when omitted")
    parser.add_boolean_argument(
        args = ("--all",),
        description = "In `available`, also list models too large for this machine's VRAM and RAM")
    return parser

# Main
def main():

    # Parse arguments
    parser = build_parser()
    args, unknown = parser.parse_known_args()

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

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
