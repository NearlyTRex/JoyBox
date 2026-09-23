#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.system as system
import joybox.archive as archive
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Rebuild zip files in place with fixed, reproducible 7-Zip settings.",
    details = (
        "Finds every `.zip` file under the input path (or takes the one file given) and\n"
        "rebuilds it with 7-Zip: the zip is extracted to a `<name>_extracted` folder beside it\n"
        "and deleted, then the folder's contents are zipped back to the original path and the\n"
        "folder is deleted.\n"
        "\n"
        "The new zip uses Deflate at level 7, leaves out NTFS timestamps, stores non-ASCII\n"
        "names as UTF-8 and asks 7-Zip for a reproducible archive.\n"
        "\n"
        "The run stops with an error at the first zip that cannot be extracted or rebuilt."),
    examples = [
        ("Rebuild every zip in a folder", "rezip_files -i /path/to/zips"),
        ("Rebuild one zip without the confirmation prompt", "rezip_files -i \"/path/to/Game (USA).zip\" --no-preview"),
    ],
    notes = [
        "The original zip is deleted before the new one is written. If the rebuild fails, the files are still in the `<name>_extracted` folder.",
        "Each zip is extracted in full next to itself, so that directory needs room for its uncompressed contents.",
        "7-Zip must be installed as a JoyBox tool.",
    ],
    see_also = ["compress_folders", "verify_archives", "decompress_archives"],
    section = "Files & Archives")
parser.add_input_path_argument(description = "A `.zip` file, or a directory searched recursively for them; must exist")
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
        if not prompts.prompt_for_preview("Rezip files deterministically", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Rezip zip files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".zip"]):
        current_file = file
        current_file_dir = paths.get_filename_directory(current_file)
        current_file_basename = paths.get_filename_basename(current_file)
        current_file_extract_dir = paths.join_paths(current_file_dir, current_file_basename + "_extracted")

        # Unzip file
        logger.log_info("Unzipping file %s ..." % current_file)
        success = archive.extract_archive(
            archive_file = current_file,
            extract_dir = current_file_extract_dir,
            delete_original = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Unable to unzip file %s" % current_file, quit_program = True)

        # Deterministically zip file
        logger.log_info("Deterministically rezipping ...")
        success = archive.create_archive_from_folder(
            archive_file = current_file,
            source_dir = current_file_extract_dir,
            delete_original = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Unable to rezip file %s" % current_file, quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
