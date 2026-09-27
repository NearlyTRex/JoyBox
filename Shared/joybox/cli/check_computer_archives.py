# Imports
import os
import os.path
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Find Windows executables that are larger than 4092 MB.",
        details = (
            "Finds every `.exe` file under the input path (or takes the one file given) and checks\n"
            "its size. The run stops with an error at the first one larger than 4092 MB\n"
            "(4,290,772,992 bytes), naming the file. 4092 MB is the volume size backup_tool uses\n"
            "when it splits archives.\n"
            "\n"
            "Nothing is written or changed, and there is no confirmation prompt."),
        examples = [
            ("Check the installers in a folder of computer games", "check_computer_archives -i /path/to/computer/games"),
        ],
        see_also = ["backup_tool", "verify_archives"],
        section = "Files & Archives")
    parser.add_input_path_argument(description = "An `.exe` file, or a directory searched recursively for them; must exist")
    parser.add_common_arguments()
    return parser

# Main
def main():

    # Parse arguments
    parser = build_parser()
    args, unknown = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

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
