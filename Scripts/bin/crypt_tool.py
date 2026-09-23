#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.cryption as cryption
import joybox.settings as settings
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths
import joybox.prompts as prompts

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Encrypt or decrypt files in place with GPG.",
    details = (
        "Processes the given file, or every file under the given directory, and writes the\n"
        "result next to the original. Encryption uses GPG symmetric AES-256. An encrypted file\n"
        "is named after the MD5 of its original filename plus `.enc` (for example\n"
        "`document.pdf` becomes `<md5>.enc`), and the original filename is stored inside it.\n"
        "Decryption reads that stored name back and restores `document.pdf`.\n"
        "\n"
        "The passphrase is read from the `[UserData.Protection]` section of the configuration,\n"
        "never from the command line: `general_passphrase` for `-t General`, `locker_passphrase`\n"
        "for `-t Locker`. The originals are deleted after a successful run unless `-k` is given."),
    examples = [
        ("Encrypt every file in a directory with the locker passphrase", "crypt_tool -i /path/to/files -e -t Locker"),
        ("Preview an encryption without changing anything", "crypt_tool -i /path/to/files -e -t Locker -p -v"),
        ("Decrypt previously encrypted files", "crypt_tool -i /path/to/encrypted/files -d -t Locker"),
        ("Encrypt files but keep the unencrypted originals", "crypt_tool -i /path/to/files -e -t Locker -k"),
        ("Encrypt a single file with the general passphrase", "crypt_tool -i /path/to/file.txt -e -t General"),
    ],
    notes = [
        "`-t` is effectively required: without it no passphrase is found and the tool stops.",
        "Give exactly one of `-e` or `-d`; with neither, nothing is done. `-e` wins if both are given.",
        "A file whose output already exists is skipped and its original is kept. Files already in the target form (`.enc` or `.menc` when encrypting, anything else when decrypting) are left alone.",
        "Locker encryption normally uses `locker_passphrase`, but a locker with its own `locker_<name>_passphrase` setting encrypts with that instead, and those files need `backup_tool` to decrypt.",
        "To encrypt or decrypt while copying to another location, use `backup_tool -r`.",
    ],
    see_also = ["backup_tool", "upload_game_files", "sync_tool"],
    section = "Backups & Lockers")
parser.add_input_path_argument(description = "File, or directory of files, to encrypt or decrypt; must exist")
parser.add_enum_argument(
    args = ("-t", "--passphrase_type"),
    arg_type = config.PassphraseType,
    description = "Which configured passphrase to use: `General` (`general_passphrase`) or `Locker` (`locker_passphrase`)")
parser.add_boolean_argument(args = ("-e", "--encrypt"), description = "Encrypt each file to `<md5 of name>.enc` beside it")
parser.add_boolean_argument(args = ("-d", "--decrypt"), description = "Decrypt each `.enc` file back to its stored original name beside it")
parser.add_boolean_argument(args = ("-k", "--keep_originals"), description = "Keep the original files instead of deleting them after processing")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.PassphraseType.GENERAL:
        passphrase = settings.get_value("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.PassphraseType.LOCKER:
        passphrase = settings.get_value("UserData.Protection", "locker_passphrase")
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
            cryption.encrypt_file(
                src = file,
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Decrypt file
    elif args.decrypt:
        for file in paths.build_file_list(input_path):
            cryption.decrypt_file(
                src = file,
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.run_main(main)
