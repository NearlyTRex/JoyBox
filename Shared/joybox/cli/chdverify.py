# Imports
from joybox import system
from joybox import chd
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import paths
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Check CHD files against their internal SHA-1 checksums with chdman.",
        details = (
            "Finds every `.chd` file under the input path (or takes the one file given) and runs\n"
            "`chdman verify` on it. A CHD passes when chdman reports that the overall SHA-1\n"
            "verification succeeded. The run stops with an error at the first CHD that fails.\n"
            "\n"
            "Nothing is written or changed."),
        examples = [
            ("Verify every CHD in a folder", "chdverify -i /path/to/chds"),
            ("Verify one CHD without the confirmation prompt", "chdverify -i \"/path/to/Game (USA).chd\" --no-preview"),
        ],
        notes = [
            "`-p` does not skip the check; chdman still reads every CHD.",
            "chdman (MameChdman) must be installed as a JoyBox tool.",
        ],
        see_also = ["chdconvert", "chdextract", "ps3_rom_tool", "verify_archives"],
        section = "Game ROMs & Images")
    parser.add_input_path_argument(description = "A `.chd` file, or a directory searched recursively for them; must exist")
    parser.add_common_arguments()
    return parser

# After a preview, verify each CHD under the input against its SHA-1; stops at the first that fails
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

    # Show preview
    if not args.no_preview:
        details = ["Path: %s" % input_path]
        if not prompts.prompt_for_preview("Verify CHD", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Convert disc image files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):

        # Verify disc chd
        logger.log_info("Verifying %s ..." % file)
        verification_success = chd.verify_disc_chd(file)
        if verification_success:
            logger.log_info("Verified!")
        else:
            logger.log_error("Verification failed!", quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
