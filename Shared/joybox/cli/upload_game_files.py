# Imports
from joybox import config
from joybox import system
from joybox import arguments
from joybox.collection import uploading
from joybox import setup
from joybox import logger
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "upload_game_files")
    parser.add_group("Game selection")
    parser.add_input_path_argument(description = "Game folder to encrypt and upload instead of the one derived from the game options")
    parser.add_game_supercategory_argument(description = "Supercategory of the games to upload")
    parser.add_game_category_argument(description = "Category of the games to upload; all categories when omitted in `Standard` mode")
    parser.add_game_subcategory_argument(description = "Subcategory (platform) of the games to upload; all of the category's subcategories when omitted in `Standard` mode")
    parser.add_game_name_argument(description = "Exact name of the game folder to upload; every game found when omitted in `Standard` mode")
    parser.add_group("Lockers")
    parser.add_enum_argument(
        args = ("-l", "--source_locker"),
        arg_type = config.LockerType,
        default = config.LockerType.LOCAL,
        description = "Locker whose game folders are selected and encrypted")
    parser.add_enum_argument(
        args = ("-m", "--generation_mode"),
        arg_type = config.GenerationModeType,
        default = config.GenerationModeType.STANDARD,
        description = "`Standard` finds games in the source locker; `Custom` takes exactly the game named by `-c`, `-s` and `-n`")
    parser.add_enum_argument(
        args = ("-d", "--dest_locker"),
        arg_type = config.LockerType,
        description = "Locker to upload to; its passphrase encrypts the files")
    parser.add_common_arguments()
    return parser

# After a preview, encrypt each selected game's folder in place, hash it and upload it to the remote locker
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get custom input path if provided
    custom_input_path = parser.get_path("input_path")

    # Collect games to process
    games_to_process = uploading.get_upload_game_roots(
        parser = parser,
        generation_mode = args.generation_mode,
        source_locker = args.source_locker,
        input_path = custom_input_path,
        verbose = args.verbose,
        exit_on_failure = args.exit_on_failure)

    # Show preview
    if not args.no_preview:
        details = [game_root for _, game_root in games_to_process]
        if not prompts.prompt_for_preview("Upload game files (encrypt and upload to %s)" % args.dest_locker, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Upload game files
    uploading.upload_game_roots(
        games_to_process,
        locker_type = args.dest_locker,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
