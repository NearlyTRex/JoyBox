# Imports
from joybox import system
from joybox.nintendo import switch
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "switch_rom_tool")
    parser.add_input_path_argument(description = "An `.xci` file, or a directory searched recursively for them; must exist")
    parser.add_boolean_argument(args = ("-t", "--trim"), description = "Trim each image into `<name>_trimmed.xci`")
    parser.add_boolean_argument(args = ("-u", "--untrim"), description = "Pad each image to full size into `<name>_untrimmed.xci`")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete the source `.xci` after it is trimmed or untrimmed")
    parser.add_common_arguments()
    return parser

# After a preview, trim or untrim each Switch XCI under the input with XCI Trimmer into a new file beside it
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Determine action
    action = "Trim" if args.trim else "Untrim" if args.untrim else None

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Switch ROM tool", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Trim or untrim the xci files
    switch.process_switch_xcis(
        input_path = input_path,
        trim = args.trim,
        untrim = args.untrim,
        delete_originals = args.delete_originals,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
