#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import cryption
import ini
import arguments
import setup
import logger
import paths
import prompts

# Parse arguments
parser = arguments.ArgumentParser(description = "Encrypt/decrypt files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-t", "--passphrase_type"),
    arg_type = config.PassphraseType,
    description = "Passphrase type")
parser.add_boolean_argument(args = ("-e", "--encrypt"), description = "Encrypt files")
parser.add_boolean_argument(args = ("-d", "--decrypt"), description = "Decrypt files")
parser.add_boolean_argument(args = ("-k", "--keep_originals"), description = "Keep original files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.PassphraseType.GENERAL:
        passphrase = ini.GetIniValue("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.PassphraseType.LOCKER:
        passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")
    if not passphrase:
        logger.log_error("No passphrase set", quit_program = True)

    # Show preview
    if not args.no_preview:
        action = "Encrypt" if args.encrypt else "Decrypt" if args.decrypt else "Unknown"
        details = [
            "Path: %s" % input_path,
            "Action: %s" % action,
            "Keep originals: %s" % args.keep_originals
        ]
        if not prompts.prompt_for_preview("%s files" % action, details):
            logger.log_warning("Operation cancelled by user")
            return

    # Encrypt file
    if args.encrypt:
        for file in paths.build_file_list(input_path):
            cryption.EncryptFile(
                src = file,
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Decrypt file
    elif args.decrypt:
        for file in paths.build_file_list(input_path):
            cryption.DecryptFile(
                src = file,
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
