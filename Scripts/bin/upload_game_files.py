#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.environment as environment
import joybox.collection as collection
import joybox.gameinfo as gameinfo
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Encrypt game folders in place and upload them to a remote locker.",
    details = (
        "For each selected game, works on its folder in the source locker\n"
        "(`Gaming/<supercategory>/<category>/<subcategory>/<game>`) or on `-i`:\n"
        "\n"
        "1. Encrypts every file in the folder with GPG (AES-256) using the destination\n"
        "   locker's passphrase. Each file becomes `<md5 of name>.enc` with its real name stored\n"
        "   inside, and the unencrypted original is deleted.\n"
        "2. Records each file's real name, XXH3 hash and size, plus the encrypted file's name,\n"
        "   MD5 and size, in the game hash metadata (`Hashes/<supercategory>/<category>/\n"
        "   <subcategory>.json` under the configured game metadata directory).\n"
        "3. Copies the encrypted folder to the same path, relative to the local locker, on the\n"
        "   destination locker.\n"
        "\n"
        "In `Standard` mode the games are the folders found in the source locker, narrowed by\n"
        "`-u`, `-c`, `-s` and `-n` (an exact folder name). In `Custom` mode `-c`, `-s` and `-n`\n"
        "are required and name exactly one game."),
    examples = [
        ("Encrypt and upload one Nintendo Switch game to Hetzner", "upload_game_files -c Nintendo -s \"Nintendo Switch\" -n \"Game Name\" -d Hetzner"),
        ("Show what would be encrypted and uploaded without changing anything", "upload_game_files -c Nintendo -s \"Nintendo Switch\" -n \"Game Name\" -d Hetzner -p -v"),
        ("Upload a Steam game", "upload_game_files -c Computer -s Steam -n \"Game Name\" -d Hetzner"),
        ("Upload a game's DLC", "upload_game_files -u DLC -c Nintendo -s \"Nintendo Switch\" -n \"Game Name\" -d Hetzner"),
        ("Upload every Nintendo Switch game in the local locker", "upload_game_files -c Nintendo -s \"Nintendo Switch\" -d Hetzner"),
        ("Upload one game from a folder of your choosing", "upload_game_files -m Custom -i /path/to/game/files -c Nintendo -s \"Nintendo Switch\" -n \"Game Name\" -d Hetzner"),
    ],
    notes = [
        "The local copies are left encrypted: the unencrypted originals are deleted. Decrypt them with `crypt_tool -d -t Locker` or copy them out decrypted with `backup_tool -r Decrypt`.",
        "Files that are already `.enc` are left as they are, so an interrupted run can be repeated.",
        "`-i` is used for every selected game, so give it only with `-m Custom` or a `-n` that matches one game.",
        "The first game that fails stops the run.",
    ],
    see_also = ["backup_tool", "crypt_tool", "sync_tool", "backup_game_files"],
    section = "Backups & Lockers")
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
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get custom input path if provided
    custom_input_path = parser.get_path("input_path")

    # Collect games to process
    games_to_process = []
    for game_info in gameinfo.iterate_selected_game_infos(
        parser = parser,
        generation_mode = args.generation_mode,
        locker_type = args.source_locker,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure):
        game_root = custom_input_path or environment.get_locker_gaming_files_dir(
            game_info.get_supercategory(),
            game_info.get_category(),
            game_info.get_subcategory(),
            game_info.get_name(),
            args.source_locker)
        games_to_process.append((game_info, game_root))

    # Show preview
    if not args.no_preview:
        details = [game_root for _, game_root in games_to_process]
        if not prompts.prompt_for_preview("Upload game files (encrypt and upload to %s)" % args.dest_locker, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Upload game files
    for game_info, game_root in games_to_process:
        success = collection.upload_game_files(
            game_info = game_info,
            game_root = game_root,
            locker_type = args.dest_locker,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error(
                message = "Upload of game files failed!",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)

# Start
if __name__ == "__main__":
    system.run_main(main)
