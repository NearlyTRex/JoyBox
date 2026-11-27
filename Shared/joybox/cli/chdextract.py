# Imports
from joybox import system
from joybox import chd
from joybox import config
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "chdextract")
    parser.add_input_path_argument(description = "A `.chd` file, or a directory searched recursively for them; must exist")
    parser.add_enum_argument(
        args = ("-f", "--format"),
        arg_type = config.DiscExtractFormatType,
        default = config.DiscExtractFormatType.CUE,
        description = "Format to write each disc in")
    parser.add_string_argument(args = ("-b", "--bin_ext"), default = ".bin", description = "Extension of the binary track file, including the dot; ignored for `ISO`")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each CHD after it is extracted")
    parser.add_common_arguments()
    return parser

# After a preview, extract each CHD under the input to a disc image beside it in the chosen sheet or ISO format
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

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Format: %s" % args.format,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Extract CHD", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Extract chd files
    chd.extract_disc_chds(
        input_path = input_path,
        extract_format = args.format,
        bin_ext = args.bin_ext,
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
