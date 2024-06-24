#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import cryption
import setup
import ini

# Parse arguments
parser = argparse.ArgumentParser(description="Encrypt/decrypt files.")
parser.add_argument("path", help="Input path")
parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt files")
parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt files")
parser.add_argument("-p", "--passphrase", type=str, help="Passphrase for encryption")
parser.add_argument("--passphrase_protection_field", type=str, default="general_passphrase", help="Passphrase protection field")
parser.add_argument("-k", "--keep_originals", action="store_true", help="Keep original files")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.path:
    parser.print_help()
    sys.exit(-1)

# Check that path exists first
root_path = os.path.realpath(args.path)
if not os.path.exists(root_path):
    system.LogError("Path '%s' does not exist" % args.path)
    sys.exit(-1)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get passphrase
    passphrase = args.passphrase
    if not passphrase or len(passphrase) == 0:
        passphrase = ini.GetIniValue("UserData.Protection", args.passphrase_protection_field)
        if len(passphrase) == 0:
            system.LogError("No passphrase set")
            sys.exit(-1)

    # Encrypt file
    if args.encrypt:
        for file in system.BuildFileList(root_path):
            cryption.EncryptFile(
                source_file = file,
                output_file = cryption.GetEncryptedFilename(file),
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

    # Decrypt file
    elif args.decrypt:
        for file in system.BuildFileList(root_path):
            cryption.DecryptFile(
                source_file = file,
                output_file = cryption.GetDecryptedFilename(file),
                passphrase = passphrase,
                delete_original = not args.keep_originals,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)

# Start
main()
