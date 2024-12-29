#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import archive
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Verify archive files.")
parser.add_input_path_argument()
parser.add_archive_type_argument(
    args = ("-a", "--archive_types"),
    default = [config.ArchiveType.ZIP],
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
    archive_extensions = [archive.GetArchiveExtension(archive_type) for archive_type in args.archive_types]
    for file in system.BuildFileListByExtensions(input_path, extensions = archive_extensions):
        system.Log("Verifying %s ..." % file)
        verification_success = archive.TestArchive(
            archive_file = file,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if verification_success:
            system.LogSuccess("Verified!")
        else:
            system.LogErrorAndQuit("Verification failed!")

# Start
main()
