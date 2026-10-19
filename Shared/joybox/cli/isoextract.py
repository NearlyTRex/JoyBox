# Imports
import joybox.config as config
import joybox.system as system
import joybox.iso as iso
import joybox.hfs as hfs
import joybox.arguments as arguments
import joybox.archive as archive
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Extract the files from ISO images into a folder beside each image.",
        details = (
            "Finds every `.iso` file under the input path (or takes the one file given) and\n"
            "extracts it into a `<name>` folder next to it. An ISO whose `<name>` folder already\n"
            "exists is skipped.\n"
            "\n"
            "With the default `-e Iso`, 7-Zip is tried first; if it fails, xorriso extracts the\n"
            "image instead, and the extracted files are then made readable and writable by\n"
            "everyone (666 for files, 777 for folders).\n"
            "With `-e Archive`, only 7-Zip is used.\n"
            "\n"
            "`-f` picks which filesystem of a hybrid Mac/PC disc to extract. `ISO` (the default)\n"
            "reads the ISO 9660 or Joliet side, which holds the Windows files. `HFS` reads the\n"
            "Mac HFS or HFS+ volume instead, found through the disc's Apple partition map or at the\n"
            "start of the image, and ignores `-e`. Each file's data fork is written as the file;\n"
            "when it also has a resource fork, a Finder type and creator or Finder flags, they are\n"
            "written beside it as an AppleDouble `._<name>` file, which macOS and netatalk read\n"
            "back. `/` in a Mac name becomes `:`. On HFS+, hard links are written as copies of\n"
            "their file, symlinks stay symlinks, the journal and other volume internals are left\n"
            "out, and files stored compressed (Mac OS X 10.6 and later) are skipped with a warning.\n"
            "\n"
            "There is no confirmation prompt; the tool starts straight away."),
        examples = [
            ("Extract every ISO in a folder", "isoextract -i /path/to/isos"),
            ("Extract and delete the ISOs, previewing first", "isoextract -i /path/to/isos -d -p -v"),
            ("Extract one image with 7-Zip only", "isoextract -i \"/path/to/Game (USA).iso\" -e Archive"),
            ("Extract the Mac side of a hybrid disc", "isoextract -i \"/path/to/Game (USA).iso\" -f HFS"),
        ],
        notes = [
            "7-Zip must be installed as a JoyBox tool, and xorriso (XorrISO) for the `-e Iso` fallback.",
            "`-f HFS` reads classic HFS volumes with the machfs Python package, holding the volume in memory.",
        ],
        see_also = ["make_iso", "decompress_archives", "chdextract"],
        section = "Game ROMs & Images")
    parser.add_input_path_argument(description = "An `.iso` file, or a directory searched recursively for them; must exist")
    parser.add_enum_argument(
        args = ("-e", "--extract_method"),
        arg_type = config.DiscExtractType,
        default = config.DiscExtractType.ISO,
        description = "`Iso` tries 7-Zip and falls back to xorriso; `Archive` uses 7-Zip only")
    parser.add_enum_argument(
        args = ("-f", "--filesystem"),
        arg_type = config.DiscFilesystemType,
        default = config.DiscFilesystemType.ISO,
        description = "Filesystem to extract from a hybrid disc: `ISO` for the ISO 9660 or Joliet side, `HFS` for the Mac side")
    parser.add_boolean_argument(args = ("-s", "--skip_existing"), description = "With `-e Archive`, keep files that already exist in the output folder instead of overwriting them")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each ISO after it is extracted")
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

    # Convert disc image files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".iso"]):

        # Get file info
        current_file = file
        current_dir = paths.get_filename_directory(current_file)
        current_basename = paths.get_filename_basename(current_file)

        # Check if output dir already exists
        output_dir = paths.join_paths(current_dir, current_basename)
        if paths.is_path_directory(output_dir):
            continue

        # Extract mac side
        if args.filesystem == config.DiscFilesystemType.HFS:
            hfs.extract_hfs(
                image_file = current_file,
                extract_dir = output_dir,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Extract as iso
        elif args.extract_method == config.DiscExtractType.ISO:
            iso.extract_iso(
                iso_file = current_file,
                extract_dir = output_dir,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

        # Extract as archive
        else:
            archive.extract_archive(
                archive_file = current_file,
                extract_dir = output_dir,
                skip_existing = args.skip_existing,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
