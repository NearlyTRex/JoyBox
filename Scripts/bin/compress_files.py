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
    description = "Compress each file in a directory into an archive of its own with 7-Zip.",
    details = (
        "Every file directly inside the input directory (subdirectories are not searched)\n"
        "whose name ends with one of the `-t` suffixes is compressed into\n"
        "`<name without extension>.<archive extension>` in the same directory. With no `-t`,\n"
        "every file is compressed. A file whose archive already exists is skipped.\n"
        "\n"
        "Zip archives use Deflate at level 7 and 7z archives use 7-Zip's default method. Both\n"
        "leave out NTFS timestamps and ask 7-Zip for a reproducible archive.\n"
        "\n"
        "With `-s` the archive is split into volumes named `<archive>.001`, `.002` and so on;\n"
        "if the file fits in one volume, it is renamed back to the plain archive name."),
    examples = [
        ("Zip every ISO in a folder", "compress_files -i /path/to/files -t .iso"),
        ("7z the ISO and BIN files and delete them, previewing first", "compress_files -i /path/to/files -a 7Z -t .iso,.bin -d -p -v"),
        ("Make password-protected 7z archives split into 4092 MB volumes", "compress_files -i /path/to/files -a 7Z -w secret -s 4092m"),
    ],
    notes = [
        "Use `ZIP` or `7Z`. Types that cannot be created, such as `RAR` or the tarball types, are refused for each file with an error.",
        "`-t` matches the end of the file name, so `iso` would also match `game.xiso`; include the dot to be exact.",
        "7-Zip must be installed as a JoyBox tool.",
    ],
    see_also = ["compress_folders", "decompress_archives", "verify_archives", "rezip_files"],
    section = "Files & Archives")
parser.add_input_path_argument(description = "Directory whose files are compressed; must exist")
parser.add_enum_argument(
    args = ("-a", "--archive_type"),
    arg_type = config.ArchiveFileType,
    default = config.ArchiveFileType.ZIP,
    description = "Archive format to create; only `ZIP` and `7Z` are supported")
parser.add_string_argument(args = ("-w", "--password"), description = "Password to encrypt the archives with; none when omitted")
parser.add_string_argument(args = ("-s", "--volume_size"), description = "Split archives into volumes of this size, in 7-Zip's `-v` format such as `100m` or `4g`; not split when omitted")
parser.add_string_argument(args = ("-t", "--file_types"), default = "", description = "Comma-separated file name suffixes to compress, such as `.iso,.bin`; empty compresses every file")
parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each file after it is compressed")
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
            "Archive type: %s" % args.archive_type,
            "File types: %s" % args.file_types,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Compress files", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Compress files
    for obj in paths.get_directory_contents(input_path):
        obj_path = paths.join_paths(input_path, obj)
        if not paths.is_path_file(obj_path):
            continue

        # Check file type
        should_compress = False
        for file_type in args.file_types.split(","):
            if obj_path.endswith(file_type):
                should_compress = True
        if not should_compress:
            continue

        # Get output file
        output_basename = paths.get_filename_basename(obj_path)
        output_ext = args.archive_type.cval()
        output_file = paths.join_paths(input_path, output_basename + output_ext)
        if os.path.exists(output_file):
            continue

        # Compress file
        archive.create_archive_from_file(
            archive_file = output_file,
            source_file = obj_path,
            password = args.password,
            volume_size = args.volume_size,
            delete_original = args.delete_originals,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
