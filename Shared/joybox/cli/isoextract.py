# Imports
from joybox import config
from joybox import system
from joybox import iso
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "isoextract")
    parser.add_input_path_argument(description = "An `.iso` or `.toast` file, or a directory searched recursively for them; must exist")
    parser.add_enum_argument(
        args = ("-e", "--extract_method"),
        arg_type = config.DiscExtractType,
        default = config.DiscExtractType.ISO,
        description = "`Iso` tries 7-Zip and falls back to xorriso; `Archive` uses 7-Zip only")
    parser.add_enum_argument(
        args = ("-f", "--filesystem"),
        arg_type = config.DiscFilesystemType,
        default = config.DiscFilesystemType.ISO,
        description = "Filesystem to extract from a hybrid disc: `ISO` for the ISO 9660 or Joliet side, `HFS` for the Mac side")
    parser.add_boolean_argument(args = ("-s", "--skip_existing"), description = "With `-e Archive`, keep files that already exist in the output folder instead of overwriting them")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each ISO after it is extracted")
    parser.add_common_arguments()
    return parser

# Extract each ISO and Toast image under the input into a folder beside it, as ISO, HFS or archive, skipping existing folders
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

    # Extract disc image files
    iso.extract_disc_images(
        input_path = input_path,
        filesystem = args.filesystem,
        extract_method = args.extract_method,
        skip_existing = args.skip_existing,
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
