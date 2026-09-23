#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.archive as archive
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Extract archive files into a folder beside each archive.",
    details = (
        "Finds every archive of the chosen types under the input path (or takes the one file\n"
        "given) and extracts it into a `<name>` folder next to it, or with `-s` straight into\n"
        "the directory the archive is in. Tarballs are extracted with tar, RAR archives with\n"
        "unrar and everything else with 7-Zip.\n"
        "\n"
        "Existing files in the output folder are overwritten, and an archive is extracted again\n"
        "even if its folder already exists."),
    examples = [
        ("Extract every zip in a folder", "decompress_archives -i /path/to/archives"),
        ("Extract zip, 7z and RAR archives and delete them, previewing first", "decompress_archives -i /path/to/archives -a ZIP 7Z RAR -d -p -v"),
        ("Extract a tarball next to itself", "decompress_archives -i /path/to/backup.tar.gz -a TAR_GZ -s"),
    ],
    notes = [
        "Archives are matched by extension only, e.g. `ZIP` selects `.zip` files and `TAR_GZ` selects `.tar.gz` files.",
        "`APPIMAGE` archives are refused with an error.",
        "7-Zip must be installed as a JoyBox tool, plus tar and unrar for those formats.",
    ],
    see_also = ["compress_files", "compress_folders", "verify_archives", "isoextract"],
    section = "Files & Archives")
parser.add_input_path_argument(description = "An archive file, or a directory searched recursively for archives; must exist")
parser.add_enum_argument(
    args = ("-a", "--archive_types"),
    arg_type = config.ArchiveFileType,
    default = [config.ArchiveFileType.ZIP],
    description = "Archive types to extract, space separated; each selects files by its extension",
    allow_multiple = True)
parser.add_boolean_argument(args = ("-s", "--same_dir"), description = "Extract into the archive's own directory instead of a `<name>` folder")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each archive after it is extracted")
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
        details = [
            "Path: %s" % input_path,
            "Archive types: %s" % [t.cval() for t in args.archive_types],
            "Same dir: %s" % args.same_dir,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Decompress archives", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Decompress archives
    archive_extensions = [archive_type.cval() for archive_type in args.archive_types]
    for file in paths.build_file_list_by_extensions(input_path, extensions = archive_extensions):

        # Get file info
        current_file = file
        file_dir = paths.get_filename_directory(current_file)
        file_basename = paths.get_filename_basename(current_file)
        output_dir = paths.join_paths(file_dir, file_basename)
        if args.same_dir:
            output_dir = file_dir

        # Decompress file
        archive.extract_archive(
            archive_file = current_file,
            extract_dir = output_dir,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
