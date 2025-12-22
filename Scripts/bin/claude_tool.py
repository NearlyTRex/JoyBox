#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import arguments
import setup
import claude
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Process files with Claude AI.")
parser.add_input_path_argument()
parser.add_output_path_argument()
parser.add_string_argument(
    args = ("-f", "--prompt_file"),
    description = "Path to prompt file (markdown or text)")
parser.add_string_argument(
    args = ("-m", "--model"),
    default = claude.DEFAULT_MODEL,
    description = "Claude model to use")
parser.add_string_argument(
    args = ("-w", "--extensions"),
    default = "",
    description = "Comma-separated file extensions to process (e.g., '.cpp,.h')")
parser.add_string_argument(
    args = ("-t", "--max_tokens"),
    default = str(claude.DEFAULT_MAX_TOKENS),
    description = "Maximum tokens in response")
parser.add_boolean_argument(
    args = ("-e", "--skip_existing"),
    description = "Skip files that already exist in output directory")
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
    if not args.pretend_run and not claude.IsConfigured():
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
    success_count, skip_count, error_count = claude.ProcessFiles(
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
