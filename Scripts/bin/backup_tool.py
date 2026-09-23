#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.backup as backup
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.fileops as fileops
import joybox.prompts as prompts

# Setup argument parser
parser = arguments.ArgumentParser(
    description = "Copy, encrypt, decrypt or archive a directory tree into another directory.",
    details = (
        "Copies every file under the source directory to the same relative path under the\n"
        "destination. With `-r Encrypt` each file is encrypted with GPG (AES-256) and stored as\n"
        "the MD5 of its filename plus `.enc`, with the real filename kept inside the encrypted\n"
        "file; `-r Decrypt` reverses this and restores the real filename. Files that are already\n"
        "in the target form (already encrypted, or not encrypted) are copied as they are.\n"
        "\n"
        "With `-b Archive` the tool instead looks two levels down: each directory at\n"
        "`<source>/<A>/<B>` becomes a 7z archive at `<destination>/<A>/<B>.7z`, split into\n"
        "4092 MB volumes. Files not inside such a directory are not archived, and `-r` is ignored.\n"
        "\n"
        "Source and destination are each resolved the same way. A path given with `-i`/`-o`\n"
        "that exists is used as is. Otherwise the path is built from a root and the game\n"
        "options: `<root>/Gaming/<supercategory>/<category>/<subcategory>/<offset>`, stopping\n"
        "at the first one not given. The root is `--input_locker_base`/`--output_locker_base`\n"
        "if given and it exists, otherwise the mount path of the `-l`/`-d` locker. When a\n"
        "locker base is given, `-i`/`-o` is ignored for that side.\n"
        "\n"
        "The encryption passphrase comes from configuration, not the command line: the\n"
        "destination locker's passphrase when encrypting, the source locker's when decrypting,\n"
        "falling back to the general locker passphrase."),
    examples = [
        ("Copy one directory into another", "backup_tool -i /path/to/source -o /path/to/destination"),
        ("Preview a copy without changing anything", "backup_tool -i /path/to/source -o /path/to/destination -p -v"),
        ("Encrypt files while copying them to a backup directory", "backup_tool -i /path/to/local/files -o /path/to/backup -r Encrypt"),
        ("Decrypt files and remove the encrypted originals", "backup_tool -i /path/to/encrypted -o /path/to/decrypted -r Decrypt --delete_original"),
        ("Resume an interrupted copy, skipping files already at the destination", "backup_tool -i /path/to/source -o /path/to/destination -e"),
        ("Copy the local locker's Nintendo Switch ROMs to an existing directory", "backup_tool -o /mnt/external/backup -u Roms -c Nintendo -s \"Nintendo Switch\""),
        ("Decrypt Nintendo Switch ROMs from the mounted Hetzner locker into the local locker", "backup_tool -l Hetzner -d Local -u Roms -c Nintendo -s \"Nintendo Switch\" -r Decrypt"),
        ("Encrypt local Nintendo Switch ROMs into the mounted Hetzner locker", "backup_tool -l Local -d Hetzner -u Roms -c Nintendo -s \"Nintendo Switch\" -r Encrypt"),
        ("Decrypt one game's updates onto an external drive, mirroring the locker layout", "backup_tool -l Hetzner --output_locker_base /media/user/External -u Updates -c Microsoft -s \"Microsoft Xbox\" -g \"Halo 2 (USA)\" -r Decrypt"),
        ("Mirror between two external drives, skipping unchanged files", "backup_tool --input_locker_base /media/user/Drive1 --output_locker_base /media/user/Drive2 -u Roms -c Nintendo -s \"Nintendo Switch\" -a"),
        ("Archive each game directory into split 7z files", "backup_tool -i /path/to/source -o /path/to/archives -b Archive"),
    ],
    notes = [
        "A remote locker (`Hetzner`, `Gdrive`) must be mounted first with `sync_tool -a Mount -l <locker>`; the tool only reads and writes its mount path.",
        "`-u` defaults to `Roms`, so a source or destination that is not an existing `-i`/`-o` path always resolves under `Gaming/Roms` unless `-u` says otherwise.",
        "The source and destination must differ. A missing destination is created only when `--output_locker_base` is given and exists.",
        "Without `-x`, a plain copy that hits an I/O error on a file removes the partial copy, appends the source path to `copy_errors.txt` in the destination, and carries on. With `-x` the run stops instead.",
        "`-a` with `-r` decrypts the existing destination file to a temporary directory and compares contents, so unchanged files are not encrypted or decrypted again.",
    ],
    see_also = ["upload_game_files", "crypt_tool", "sync_tool", "master_backup"],
    section = "Backups & Lockers")
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
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get source file root
    source_file_root = backup.resolve_path(
        path = args.input_path,
        locker_type = args.source_locker,
        base_path = args.input_locker_base,
        game_supercategory = args.game_supercategory,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_offset = args.game_offset)
    if not paths.is_path_directory(source_file_root):
        logger.log_error("Could not resolve source path", quit_program = True)

    # Get destination file root
    dest_file_root = backup.resolve_path(
        path = args.output_path,
        locker_type = args.dest_locker,
        base_path = args.output_locker_base,
        game_supercategory = args.game_supercategory,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_offset = args.game_offset)
    if not paths.is_path_directory(dest_file_root):
        if args.output_locker_base and paths.is_path_directory(args.output_locker_base):
            fileops.make_directory(dest_file_root, verbose = args.verbose, pretend_run = args.pretend_run)
        else:
            logger.log_error("Could not resolve destination path", quit_program = True)

    # Prevent source == destination
    if paths.are_paths_equal(source_file_root, dest_file_root):
        logger.log_error("Source and destination paths cannot be the same", quit_program = True)

    # Show preview
    if not args.no_preview:
        details = [
            "Source: %s" % source_file_root,
            "Destination: %s" % dest_file_root,
            "Type: %s" % args.backup_type
        ]
        if args.cryption_type != config.CryptionType.NONE:
            details.append("Cryption: %s" % args.cryption_type)
        if not prompts.prompt_for_preview("Backup files", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Get exclude paths (filter empty strings)
    exclude_paths = [p for p in args.exclude_paths.split(",") if p]

    # Copy files
    if args.backup_type == config.BackupType.COPY:
        if args.cryption_type == config.CryptionType.ENCRYPT:
            passphrase_locker = args.dest_locker
        elif args.cryption_type == config.CryptionType.DECRYPT:
            passphrase_locker = args.source_locker
        else:
            passphrase_locker = None
        skip_on_error = not args.exit_on_failure
        error_log_path = paths.join_paths(dest_file_root, "copy_errors.txt") if skip_on_error else None
        backup.copy_files(
            input_base_path = source_file_root,
            output_base_path = dest_file_root,
            cryption_type = args.cryption_type,
            locker_type = passphrase_locker,
            exclude_paths = exclude_paths,
            delete_original = args.delete_original,
            show_progress = True,
            skip_existing = args.skip_existing,
            skip_identical = args.skip_identical,
            skip_on_error = skip_on_error,
            error_log_path = error_log_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Archive files
    elif args.backup_type == config.BackupType.ARCHIVE:
        backup.archive_sub_folders(
            input_base_path = source_file_root,
            output_base_path = dest_file_root,
            archive_type = config.ArchiveFileType.SEVENZIP,
            exclude_paths = exclude_paths,
            show_progress = True,
            skip_existing = args.skip_existing,
            skip_identical = args.skip_identical,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
