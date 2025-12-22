#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import programs
import command
import arguments
import setup
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "List duplicate files.")
parser.add_input_path_argument()
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
    if programs.IsToolInstalled("JDupes"):
        dupes_tool = programs.GetToolProgram("JDupes")
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
    code = command.RunReturncodeCommand(
        cmd = list_cmd,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if code != 0:
        logger.log_error("List command failed with code %d" % code)

# Start
if __name__ == "__main__":
    system.run_main(main)
