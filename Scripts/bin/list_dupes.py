#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.system as system
import joybox.programs as programs
import joybox.command as command
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "List duplicate files under a directory.",
    details = (
        "Runs jdupes over the directory and all its subdirectories and prints each set of\n"
        "files with identical content, with their sizes, followed by a summary of how many\n"
        "duplicates there are and how much space they take. Nothing is deleted or changed."),
    examples = [
        ("List duplicates in a directory tree", "list_dupes -i ~/Downloads"),
    ],
    notes = [
        "jdupes must be installed with `setup_tools -k JDupes`; the command exits with an error if it is not found.",
    ],
    see_also = ["setup_tools", "sanitize_filenames"],
    section = "Files & Archives")
parser.add_input_path_argument(description = "Directory to search, including all subdirectories; it must exist")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Get tool
    dupes_tool = None
    if programs.is_tool_installed("JDupes"):
        dupes_tool = programs.get_tool_program("JDupes")
    if not dupes_tool:
        logger.log_error("JDupes was not found", quit_program = True)

    # Get list command
    list_cmd = [
        dupes_tool,
        "--recurse",
        "--print-summarize",
        "--size",
        input_path
    ]

    # Run list command
    code = command.run_returncode_command(
        cmd = list_cmd,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if code != 0:
        logger.log_error("List command failed with code %d" % code)

# Start
if __name__ == "__main__":
    system.run_main(main)
