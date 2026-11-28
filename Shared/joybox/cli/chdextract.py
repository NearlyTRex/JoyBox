# Imports
from joybox import system
from joybox import chd
from joybox import config
from joybox import arguments
from joybox import setup
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

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    details = [
        "Path: %s" % input_path,
        "Format: %s" % args.format,
        "Delete originals: %s" % args.delete_originals
    ]
    if not prompts.confirm_preview(args.no_preview, "Extract CHD", details):
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
