#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import cryption
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Encrypt/decrypt files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt files")
parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt files")
parser.add_argument("-t", "--passphrase_type",
    choices=config.PassphraseType.values(),
    default=config.PassphraseType.GENERAL,
    help="Passphrase type"
)
parser.add_argument("-k", "--keep_originals", action="store_true", help="Keep original files")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    system.QuitProgram()

# Check that path exists first
root_path = os.path.realpath(args.path)
if not os.path.exists(root_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get passphrase
    passphrase = None
    if args.passphrase_type == config.PassphraseType.GENERAL:
        passphrase = ini.GetIniValue("UserData.Protection", "general_passphrase")
    elif args.passphrase_type == config.PassphraseType.LOCKER:
        passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")
    if not passphrase:
        system.LogErrorAndQuit("No passphrase set")

    # Encrypt file
    if args.encrypt:
        for file in system.BuildFileList(root_path):
            cryption.EncryptFile(
                source_file = file,
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

    # Decrypt file
    elif args.decrypt:
        for file in system.BuildFileList(root_path):
            cryption.DecryptFile(
                source_file = file,
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Start
main()
