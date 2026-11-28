# Imports
from joybox import system
from joybox import asset
from joybox import arguments
from joybox import setup

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "clean_exif_data")
    parser.add_input_path_argument(description = "Image file, or directory to process recursively; it must exist")
    parser.add_common_arguments()
    return parser

# Strip every EXIF and embedded metadata tag from the input image or directory in place with ExifTool
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Clean exif data
    asset.clean_exif_data(
        asset_file = input_path,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
