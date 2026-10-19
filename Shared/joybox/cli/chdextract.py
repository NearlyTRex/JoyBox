# Imports
import os
import os.path
import joybox.system as system
import joybox.chd as chd
import joybox.config as config
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Extract CD disc images from CHD files with chdman.",
        details = (
            "Finds every `.chd` file under the input path (or takes the one file given) and runs\n"
            "`chdman extractcd` on it, writing the disc next to it in the format `-f` picks:\n"
            "\n"
            "- `CUE`: a CUE sheet `<name>.cue` and the track data `<name>.bin`\n"
            "- `GDI`: a GDI sheet `<name>.gdi` and its tracks, for Dreamcast discs\n"
            "- `TOC`: a cdrdao TOC `<name>.toc` and the track data `<name>.bin`\n"
            "- `ISO`: an ISO image `<name>.iso`\n"
            "\n"
            "`-b` changes the `.bin` extension of the sheet formats.\n"
            "\n"
            "`ISO` extracts the CHD to CUE/BIN in a temporary folder and splits it with `bchunk`.\n"
            "A disc that is one 2048-byte data track (a CHD made from an ISO) is already an ISO\n"
            "and skips bchunk. A disc with more than one track keeps bchunk's numbered names\n"
            "(`<name>01.iso`, `<name>02.cdr`, ...).\n"
            "\n"
            "A CHD is skipped when any of its output files already exists."),
        examples = [
            ("Extract every CHD in a folder to CUE/BIN", "chdextract -i /path/to/chds"),
            ("Extract to CUE/BIN and delete the CHDs, previewing first", "chdextract -i /path/to/chds -d -p -v"),
            ("Extract a Dreamcast CHD with a GDI sheet", "chdextract -i \"/path/to/Game (USA).chd\" -f GDI"),
            ("Extract every CHD in a folder to ISO", "chdextract -i /path/to/chds -f ISO"),
        ],
        notes = [
            "chdman (MameChdman) must be installed as a JoyBox tool.",
            "`ISO` also needs bchunk (Bchunk).",
        ],
        see_also = ["chdconvert", "chdverify", "chdzip", "isoextract"],
        section = "Game ROMs & Images")
    parser.add_input_path_argument(description = "A `.chd` file, or a directory searched recursively for them; must exist")
    parser.add_enum_argument(
        args = ("-f", "--format"),
        arg_type = config.DiscExtractFormatType,
        default = config.DiscExtractFormatType.CUE,
        description = "Format to write each disc in")
    parser.add_string_argument(args = ("-b", "--bin_ext"), default = ".bin", description = "Extension of the binary track file, including the dot; ignored for `ISO`")
    parser.add_boolean_argument(args = ("-d", "--delete_originals"), description = "Delete each CHD after it is extracted")
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

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Format: %s" % args.format,
            "Delete originals: %s" % args.delete_originals
        ]
        if not prompts.prompt_for_preview("Extract CHD", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Convert disc image files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):

        # Get file info
        current_file = file
        current_dir = paths.get_filename_directory(current_file)
        current_basename = paths.get_filename_basename(current_file)

        # Extract disc chd to iso
        if args.format == config.DiscExtractFormatType.ISO:
            output_iso = paths.join_paths(current_dir, current_basename + ".iso")
            output_track = paths.join_paths(current_dir, current_basename + "01.iso")
            if os.path.exists(output_iso) or os.path.exists(output_track):
                continue
            chd.extract_disc_chd_to_iso(
                chd_file = current_file,
                iso_file = output_iso,
                delete_original = args.delete_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            continue

        # Check if output already exists
        output_bin = paths.join_paths(current_dir, current_basename + args.bin_ext)
        output_toc = paths.join_paths(current_dir, current_basename + args.format.cval())
        if os.path.exists(output_bin) or os.path.exists(output_toc):
            continue

        # Extract disc chd
        chd.extract_disc_chd(
            chd_file = current_file,
            binary_file = output_bin,
            toc_file = output_toc,
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
