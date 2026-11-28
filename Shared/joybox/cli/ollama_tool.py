# Imports
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import ollamaactions

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "ollama_tool")
    parser.add_string_argument(
        args = ("action",),
        description = "Action to perform: `list`, `available`, `best`, `pull`, `delete`, `info`, `harness`, `code` or `update`")
    parser.add_string_argument(
        args = ("-p", "--purpose"),
        description = "Purpose to filter or pick for: `chat`, `tools`, `reasoning`, `vision`, `embedding` or `cloud`")
    parser.add_string_argument(
        args = ("-m", "--model"),
        description = "Model for `pull`, `delete`, `info`, `harness` and `code`: a base name such as `qwen2.5-coder:7b` or a full tag; prompts for one when omitted")
    parser.add_string_argument(
        args = ("-H", "--harness"),
        default = None,
        description = "Coding-agent CLI for the `harness` and `code` actions: `claude_code`, `codex`, `opencode`, `aider` or `hermes`; `claude_code` when omitted")
    parser.add_boolean_argument(
        args = ("--all",),
        description = "In `available`, also list models too large for this machine's VRAM and RAM")
    return parser

# Run the chosen Ollama action: find, pull or manage models sized to this machine, or run a coding agent on one
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Run action
    return ollamaactions.run_action(
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
