# Imports
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import claude
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "claude_tool")
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
    return parser

# After a preview, send each matching file in the input tree to Claude through the prompt template and write the replies to a mirrored output tree
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input/output paths
    input_path = parser.get_input_path()
    output_path = args.output_path

    # Validate the prompt file and API key, and parse the extensions
    claude.check_process_requirements(args.prompt_file, pretend_run = args.pretend_run)
    extensions = claude.parse_extensions(args.extensions)

    # Show preview
    if not args.no_preview:
        details = claude.get_process_preview_details(input_path, output_path, args.prompt_file, args.model, extensions)
        if not prompts.prompt_for_preview("Process files with Claude", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Process files
    claude.process_files_with_summary(
        input_path = input_path,
        output_path = output_path,
        prompt_file = args.prompt_file,
        extensions = extensions,
        model = args.model,
        max_tokens = int(args.max_tokens),
        skip_existing = args.skip_existing,
        verbose = args.verbose,
        pretend_run = args.pretend_run)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
