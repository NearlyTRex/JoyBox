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
import joybox.claude as claude
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Run every file in a directory through Claude with a prompt template.",
    details = (
        "Walks the input directory, fills the prompt template with each file's content, sends\n"
        "it to the Anthropic API, and writes the reply to the same relative path under the\n"
        "output directory, so the output mirrors the input tree. Files are sent one at a time.\n"
        "It suits bulk rewrites such as cleaning up decompiled code, generating documentation,\n"
        "or converting formats.\n"
        "\n"
        "The prompt file is plain text or markdown. These placeholders are replaced for each\n"
        "file: `{file_content}` (the whole file), `{filename}` (e.g. `main.cpp`),\n"
        "`{file_basename}` (`main`), `{file_extension}` (`.cpp`), `{input_file}` (full path),\n"
        "`{input_dir}` and `{output_dir}` (the directories given with `-i` and `-o`).\n"
        "\n"
        "The API key is read from `[UserData.Anthropic] anthropic_api_key` in `~/JoyBox.ini`.\n"
        "A file that fails is counted as an error and processing moves on; the run ends with a\n"
        "count of successes, skips and errors."),
    examples = [
        ("Process every file in a directory", "claude_tool -i ./input -o ./output -f prompt.md"),
        ("Clean up Ghidra C++ output only", "claude_tool -i ./src -o ./cleaned -f ghidra_cleanup.md -w \".cpp,.h,.c\""),
        ("Use a specific model with a longer reply limit", "claude_tool -i ./input -o ./output -f prompt.md -m claude-sonnet-4-20250514 -t 16384"),
        ("Resume an interrupted run, skipping files already written", "claude_tool -i ./input -o ./output -f prompt.md -e"),
        ("List what would be processed without calling the API", "claude_tool -i ./input -o ./output -f prompt.md -p -v"),
    ],
    notes = [
        "API usage is billed per token; check the file count in the preview before confirming.",
        "Replies are written as-is, so ask the prompt for output without explanations or markdown fences if the result should be a source file.",
        "Large files may need a higher `--max_tokens`, or the reply is cut off.",
        "The `anthropic` Python package must be installed; the bootstrap's Python packages include it.",
        "A dry run does not need an API key.",
    ],
    see_also = ["decompiler_tool", "llm_chat", "ollama_tool"],
    section = "AI")
parser.add_group("Input/Output")
parser.add_input_path_argument(description = "Directory of files to process; it must exist")
parser.add_output_path_argument(description = "Directory to write the replies into, mirroring the input tree; created if missing")
parser.add_string_argument(
    args = ("-f", "--prompt_file"),
    description = "Prompt template file (text or markdown) with `{file_content}` and other placeholders; required")
parser.add_group("Behavior")
parser.add_string_argument(
    args = ("-m", "--model"),
    default = claude.DEFAULT_MODEL,
    description = "Anthropic model id to send requests to")
parser.add_string_argument(
    args = ("-w", "--extensions"),
    default = "",
    description = "Comma-separated file extensions to process, e.g. `.cpp,.h` (the dot is optional); every file when omitted")
parser.add_string_argument(
    args = ("-t", "--max_tokens"),
    default = str(claude.DEFAULT_MAX_TOKENS),
    description = "Maximum number of tokens in each reply")
parser.add_boolean_argument(
    args = ("-e", "--skip_existing"),
    description = "Skip input files whose output file already exists, to resume an interrupted run")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input/output paths
    input_path = parser.get_input_path()
    output_path = args.output_path

    # Validate prompt file
    prompt_file = args.prompt_file
    if not prompt_file:
        logger.log_error("Prompt file is required (-f/--prompt_file)", quit_program = True)
    if not paths.does_path_exist(prompt_file):
        logger.log_error("Prompt file not found: %s" % prompt_file, quit_program = True)

    # Check API key is configured
    if not args.pretend_run and not claude.is_configured():
        logger.log_error("Anthropic API key not configured", quit_program = True)

    # Parse extensions
    extensions = []
    if args.extensions:
        extensions = [ext.strip() for ext in args.extensions.split(",") if ext.strip()]
        extensions = [ext if ext.startswith(".") else "." + ext for ext in extensions]

    # Show preview
    if not args.no_preview:
        if extensions:
            file_count = len(paths.build_file_listByExtensions(input_path, extensions = extensions))
        else:
            file_count = len(paths.build_file_list(input_path))
        details = [
            "Input: %s" % input_path,
            "Output: %s" % output_path,
            "Prompt: %s" % prompt_file,
            "Model: %s" % args.model,
            "Files: %d" % file_count
        ]
        if extensions:
            details.append("Extensions: %s" % ", ".join(extensions))
        if not prompts.prompt_for_preview("Process files with Claude", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Process files
    success_count, skip_count, error_count = claude.process_files(
        input_path = input_path,
        output_path = output_path,
        prompt_file = prompt_file,
        extensions = extensions,
        model = args.model,
        max_tokens = int(args.max_tokens),
        skip_existing = args.skip_existing,
        verbose = args.verbose,
        pretend_run = args.pretend_run)

    # Summary
    if error_count > 0:
        logger.log_warning("Completed: %d success, %d skipped, %d errors" % (success_count, skip_count, error_count))
    else:
        logger.log_info("Completed: %d success, %d skipped, %d errors" % (success_count, skip_count, error_count))

# Start
if __name__ == "__main__":
    system.run_main(main)
