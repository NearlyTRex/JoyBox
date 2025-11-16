#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import archive
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Verify archive files.")
parser.add_input_path_argument()
parser.add_enum_argument(
    args = ("-a", "--archive_types"),
    arg_type = config.ArchiveFileType,
    default = [config.ArchiveFileType.ZIP],
    description = "Archive types",
    allow_multiple = True)
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Verify archives
    archive_extensions = [archive_type.cval() for archive_type in args.archive_types]
    for file in system.BuildFileListByExtensions(input_path, extensions = archive_extensions):
        system.LogInfo("Verifying %s ..." % file)
        verification_success = archive.TestArchive(
            archive_file = file,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if verification_success:
            system.LogInfo("Verified!")
        else:
            system.LogError("Verification failed!", quit_program = True)

# Start
if __name__ == "__main__":
    system.RunMain(main)
