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
import prompts

# Setup argument parser
parser = arguments.ArgumentParser(description = "Backup tool.")
parser.add_input_path_argument()
parser.add_output_path_argument()
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
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.LOCAL,
    description = "Source type")
parser.add_enum_argument(
    args = ("-q", "--destination_type"),
    arg_type = config.SourceType,
    default = config.SourceType.LOCAL,
    description = "Destination type")
parser.add_string_argument(args = ("-w", "--exclude_paths"), default = "", description = "Excluded paths (comma separated list)")
parser.add_boolean_argument(args = ("-e", "--skip_existing"), description = "Skip existing files")
parser.add_boolean_argument(args = ("-a", "--skip_identical"), description = "Skip identical files")
parser.add_enum_argument(
    args = ("-r", "--cryption_type"),
    arg_type = config.CryptionType,
    default = config.CryptionType.NONE,
    description = "Cryption type (encrypt or decrypt files during copy)")
parser.add_enum_argument(
    args = ("-k", "--locker_type"),
    arg_type = config.LockerType,
    default = config.LockerType.HETZNER,
    description = "Locker type (for encryption passphrase)")
parser.add_boolean_argument(args = ("-d", "--delete_original"), description = "Delete original files after encrypt/decrypt")
parser.add_common_arguments()
args, unknownargs = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get source file root
    source_file_root = backup.ResolvePath(
        path = args.input_path,
        source_type = args.source_type,
        game_supercategory = args.game_supercategory,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_offset = args.game_offset)
    if not paths.is_path_directory(source_file_root):
        logger.log_error("Could not resolve source path", quit_program = True)

    # Get destination file root
    dest_file_root = backup.ResolvePath(
        path = args.output_path,
        source_type = args.destination_type,
        game_supercategory = args.game_supercategory,
        game_category = args.game_category,
        game_subcategory = args.game_subcategory,
        game_offset = args.game_offset)
    if not paths.is_path_directory(dest_file_root):
        logger.log_error("Could not resolve destination path", quit_program = True)

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
        backup.CopyFiles(
            input_base_path = source_file_root,
            output_base_path = dest_file_root,
            cryption_type = args.cryption_type,
            locker_type = args.locker_type,
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
        backup.ArchiveFiles(
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
