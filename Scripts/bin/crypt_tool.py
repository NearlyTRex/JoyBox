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

    # Get input path
    input_path = parser.get_input_path()

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.PassphraseType.GENERAL:
        passphrase = ini.GetIniValue("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.PassphraseType.LOCKER:
        passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")
    if not passphrase:
        system.LogError("No passphrase set", quit_program = True)

    # Encrypt file
    if args.encrypt:
        for file in system.BuildFileList(input_path):
            cryption.EncryptFile(
                src = file,
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Decrypt file
    elif args.decrypt:
        for file in system.BuildFileList(input_path):
            cryption.DecryptFile(
                src = file,
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
main()
