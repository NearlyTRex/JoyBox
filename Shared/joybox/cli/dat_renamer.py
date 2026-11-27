# Imports
from joybox import system
from joybox import dat
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "dat_renamer")
    parser.add_input_path_argument(description = "Directory of files to rename, searched recursively. Required")
    parser.add_string_argument(args = ("-d", "--dat_directory"), description = "Directory of clrmamepro XML `.dat` files to read ROM records from")
    parser.add_string_argument(args = ("-c", "--dat_cachefile"), description = "Cache file to read ROM records from, or with `-g` to write them to")
    parser.add_boolean_argument(args = ("-g", "--generate_cachefile"), description = "With `-d`, write the collected records to the `-c` cache file")
    parser.add_common_arguments()
    return parser

# After a preview, rename each file under the input to the ROM name its MD5 matches in the DAT files or DAT cache
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Get dat directory and cachefile
    dat_directory = parser.get_path("dat_directory") or ""
    dat_cachefile = parser.get_path("dat_cachefile") or ""

    # Show preview
    if not args.no_preview:
        details = ["Input path: %s" % input_path]
        if dat_directory:
            details.append("DAT directory: %s" % dat_directory)
        if dat_cachefile:
            details.append("DAT cachefile: %s" % dat_cachefile)
        if not prompts.prompt_for_preview("Rename files using DAT", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Rename files
    dat.rename_files_using_dat(
        input_dir = input_path,
        dat_directory = dat_directory,
        dat_cachefile = dat_cachefile,
        generate_cachefile = args.generate_cachefile,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
