#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import backup
import arguments
import setup
import logger
import paths
import fileops
import prompts

# Setup argument parser
parser = arguments.ArgumentParser(description = "Backup tool.")
parser.add_input_path_argument()
parser.add_output_path_argument()
parser.add_string_argument(args = ("--input_locker_base",), default = None, description = "Alternate locker base for source (game paths will be resolved under this)")
parser.add_string_argument(args = ("--output_locker_base",), default = None, description = "Alternate locker base for destination (game paths will be mirrored under this)")
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_offset_argument()
parser.add_enum_argument(
    args = ("-b", "--backup_type"),
    arg_type = config.BackupType,
    default = config.BackupType.COPY,
    description = "Backup type")
parser.add_enum_argument(
    args = ("-l", "--source_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.LOCAL,
    description = "Source locker type")
parser.add_enum_argument(
    args = ("-d", "--dest_locker"),
    arg_type = config.LockerType,
    default = config.LockerType.LOCAL,
    description = "Destination locker type")
parser.add_string_argument(args = ("-w", "--exclude_paths"), default = "", description = "Excluded paths (comma separated list)")
parser.add_boolean_argument(args = ("-e", "--skip_existing"), description = "Skip existing files")
parser.add_boolean_argument(args = ("-a", "--skip_identical"), description = "Skip identical files")
parser.add_enum_argument(
    args = ("-r", "--cryption_type"),
    arg_type = config.CryptionType,
    default = config.CryptionType.NONE,
    description = "Cryption type (encrypt or decrypt files during copy)")
parser.add_boolean_argument(args = ("--delete_original",), description = "Delete original files after encrypt/decrypt")
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
