# Imports
import os
import os.path
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import paths

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "check_computer_archives")
    parser.add_input_path_argument(description = "An `.exe` file, or a directory searched recursively for them; must exist")
    parser.add_common_arguments()
    return parser

# Fail at the first .exe under the input larger than the 4092 MB archive volume size
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Check computer archives
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".exe"]):

        # Check exe size
        logger.log_info("Checking exe file %s ..." % file)
        exe_filesize = os.path.getsize(file)
        if exe_filesize > 4290772992:
            logger.log_error("Executable '%s' is larger than 4092 MB" % file, quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
