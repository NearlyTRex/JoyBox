#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import playstation
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Sony PlayStation Network rom tool.")
parser.add_input_path_argument()
parser.add_boolean_argument(args = ("-r", "--rename"), description = "Rename PSN files using content ids")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    if not args.no_preview:
        details = [
            "Path: %s" % input_path,
            "Action: Rename PSN files"
        ]
        if not system.PromptForPreview("PSN ROM tool", details):
            system.LogWarning("Operation cancelled by user")
            return

    # Rename psn files
    if args.rename:
        for rap_file in system.BuildFileListByExtensions(input_path, extensions = [".rap"]):
            playstation.RenamePSNRapFile(
                rap_file = rap_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
        for pkg_file in system.BuildFileListByExtensions(input_path, extensions = [".pkg"]):
            playstation.RenamePSNPackageFile(
                pkg_file = pkg_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
        for bin_file in system.BuildFileListByExtensions(input_path, extensions = [".bin"]):
            if bin_file.endswith(".work.bin"):
                playstation.RenamePSNWorkBinFile(
                    workbin_file = bin_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
        for rif_file in system.BuildFileListByExtensions(input_path, extensions = [".rif"]):
            if rif_file.endswith(".fake.rif"):
                playstation.RenamePSNFakeRifFile(
                    fakerif_file = rif_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
