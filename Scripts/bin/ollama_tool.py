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
    description = "Coding-agent harness for the 'harness' action: claude_code, codex, opencode (default: claude_code)")
parser.add_boolean_argument(
    args = ("--all",),
    description = "Show all models including those that exceed VRAM")
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
