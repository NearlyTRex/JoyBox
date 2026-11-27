# Imports
from joybox import config
from joybox import system
from joybox import iso
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "make_iso")
    parser.add_input_path_argument(description = "Directory holding the folders or zip files to turn into images; must exist")
    parser.add_enum_argument(
        args = ("-t", "--disc_source_type"),
        arg_type = config.DiscSourceType,
        default = config.DiscSourceType.FOLDER,
        description = "`Folder` images each top-level folder; `Zip` images the contents of each zip file")
    parser.add_string_argument(args = ("-n", "--volume_name"), default = "", description = "Volume name written into every image; ignored when `-a` is given")
    parser.add_boolean_argument(args = ("-a", "--auto_volume_name"), description = "Use each folder's name, or each zip's name without its extension, as its volume name")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete the source folders, or the zips and their extracted folders, once each image is made")
    parser.add_common_arguments()
    return parser

# Build an ISO from each folder in the input dir, or from each zip under it after extracting it, skipping existing ISOs
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

    # Create iso images from folders or zips
    iso.create_isos(
        input_path = input_path,
        disc_source_type = args.disc_source_type,
        volume_name = args.volume_name,
        auto_volume_name = args.auto_volume_name,
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
