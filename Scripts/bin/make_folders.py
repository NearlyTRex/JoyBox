#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.system as system
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.fileops as fileops
import joybox.paths as paths

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Move each matching file into a folder of its own, named after the file.",
    details = (
        "For every file directly inside the input directory whose name ends with one of the\n"
        "given extensions, creates a folder named after the file without its extension and\n"
        "moves the file into it. `Game (USA).iso` becomes `Game (USA)/Game (USA).iso`.\n"
        "Subdirectories and files with other extensions are left alone."),
    examples = [
        ("Put each disc image and archive in its own folder", "make_folders -i ~/Roms/PS2"),
        ("Only handle ISO and CHD files", "make_folders -i ~/Roms/PS2 -f .iso,.chd"),
        ("Preview the moves", "make_folders -i ~/Roms/PS2 -p -v"),
    ],
    notes = [
        "Extensions are matched case-sensitively and must not contain spaces, so `.iso` does not match `GAME.ISO`.",
        "There is no confirmation prompt; use `-p -v` to see what would move first.",
    ],
    see_also = ["sanitize_filenames", "compress_folders"],
    section = "Files & Archives")
parser.add_input_path_argument(description = "Directory whose top-level files are sorted into folders; it must exist")
parser.add_string_argument(args = ("-f", "--file_types"), default = ".iso,.chd,.rvz,.zip,.7z,.rar,.pkg", description = "Comma-separated filename endings to match, with the leading dot")
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

    # Make folders from file types
    for obj in paths.get_directory_contents(input_path):
        obj_path = paths.join_paths(input_path, obj)
        if paths.is_path_file(obj_path):
            if obj.endswith(tuple(args.file_types.split(","))):
                selected_file = obj_path
                selected_file_basename = paths.get_filename_basename(selected_file)
                new_folder = paths.join_paths(input_path, selected_file_basename)
                new_file = paths.join_paths(input_path, selected_file_basename, obj)
                fileops.make_directory(
                    src = new_folder,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                fileops.move_file_or_directory(
                    src = selected_file,
                    dest = new_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
