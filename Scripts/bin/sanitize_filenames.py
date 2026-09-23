#!/usr/bin/env python3

# Imports
import os
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.fileops as fileops
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Rename files so their names are plain ASCII and safe on every filesystem.",
    details = (
        "Renames each file directly inside the input directory. Accented and other non-ASCII\n"
        "characters are transliterated to ASCII (`Pokémon` becomes `Pokemon`) or dropped, the\n"
        "characters `< > : \" / \\ | ? *` and control characters are removed, trailing spaces and\n"
        "dots are stripped, and runs of spaces collapse to one.\n"
        "\n"
        "Subdirectories and the files inside them are not touched."),
    examples = [
        ("Sanitize the names of files in a directory", "sanitize_filenames -i ~/Downloads/Soundtrack"),
        ("Preview the renames without the confirmation prompt", "sanitize_filenames -i ~/Downloads/Soundtrack -p -v --no-preview"),
    ],
    notes = [
        "If the cleaned name is already taken, that file is left with its old name.",
        "It stops at the first rename that fails.",
    ],
    see_also = ["make_folders", "list_dupes"],
    section = "Files & Archives")
parser.add_input_path_argument(description = "Directory whose top-level files are renamed; it must exist")
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

    # Show preview
    if not args.no_preview:
        details = ["Path: %s" % input_path]
        if not prompts.prompt_for_preview("Sanitize filenames", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Sanitize filenames
    fileops.sanitize_filenames(
        path = input_path,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
