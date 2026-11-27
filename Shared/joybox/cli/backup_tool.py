# Imports
from joybox import config
from joybox import system
from joybox import backup
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "backup_tool")
    parser.add_group("Paths")
    parser.add_input_path_argument(description = "Source directory, used as is when it exists")
    parser.add_output_path_argument(description = "Destination directory, used as is when it exists")
    parser.add_string_argument(args = ("--input_locker_base",), default = None, description = "Directory to use as the source locker root instead of the `-l` locker's mount path; the game options are resolved under it and `-i` is ignored")
    parser.add_string_argument(args = ("--output_locker_base",), default = None, description = "Directory to use as the destination locker root instead of the `-d` locker's mount path; the game options are mirrored under it, the destination is created if missing, and `-o` is ignored")
    parser.add_group("Game path")
    parser.add_game_supercategory_argument(description = "Game supercategory folder under `Gaming` used to build a locker path")
    parser.add_game_category_argument(description = "Game category folder under the supercategory")
    parser.add_game_subcategory_argument(description = "Game subcategory (platform) folder under the category; used only with `-c`")
    parser.add_game_offset_argument(description = "Further relative path under the subcategory, such as one game's folder; used only with `-s`")
    parser.add_group("Behavior")
    parser.add_enum_argument(
        args = ("-b", "--backup_type"),
        arg_type = config.BackupType,
        default = config.BackupType.COPY,
        description = "`Copy` copies files one by one; `Archive` packs each second-level directory into a split 7z archive")
    parser.add_enum_argument(
        args = ("-l", "--source_locker"),
        arg_type = config.LockerType,
        default = config.LockerType.LOCAL,
        description = "Locker whose mount path is the source root, and whose passphrase is used when decrypting")
    parser.add_enum_argument(
        args = ("-d", "--dest_locker"),
        arg_type = config.LockerType,
        default = config.LockerType.LOCAL,
        description = "Locker whose mount path is the destination root, and whose passphrase is used when encrypting")
    parser.add_string_argument(args = ("-w", "--exclude_paths"), default = "", description = "Comma-separated path prefixes, relative to the source; files whose relative path starts with one are left out")
    parser.add_boolean_argument(args = ("-e", "--skip_existing"), description = "Skip a file when its destination already exists")
    parser.add_boolean_argument(args = ("-a", "--skip_identical"), description = "Skip a file when its destination already exists with the same content")
    parser.add_enum_argument(
        args = ("-r", "--cryption_type"),
        arg_type = config.CryptionType,
        default = config.CryptionType.NONE,
        description = "Encrypt or decrypt each file while copying; `None` copies files unchanged. Applies to `Copy` only")
    parser.add_boolean_argument(args = ("--delete_original",), description = "Delete each source file after it has been encrypted or decrypted; has no effect on a plain copy")
    parser.add_common_arguments()
    return parser

# After a preview, copy the source tree into the destination, encrypting or decrypting each file, or pack its second-level folders into split 7z archives
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Back up the source tree into the destination, after a preview
    backup.backup_tree(
        input_path = args.input_path,
        output_path = args.output_path,
        source_locker = args.source_locker,
        dest_locker = args.dest_locker,
        input_locker_base = args.input_locker_base,
        output_locker_base = args.output_locker_base,
        game_supercategory = args.game_supercategory,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_offset = args.game_offset,
        backup_type = args.backup_type,
        cryption_type = args.cryption_type,
        exclude_paths = args.exclude_paths,
        delete_original = args.delete_original,
        skip_existing = args.skip_existing,
        skip_identical = args.skip_identical,
        show_preview = not args.no_preview,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
