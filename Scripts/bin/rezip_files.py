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
parser = arguments.ArgumentParser(description = "Rezip files deterministically.")
parser.add_input_path_argument()
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get input path
    input_path = parser.get_input_path()

    # Rezip zip files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".zip"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)
        current_file_extract_dir = os.path.join(current_file_dir, current_file_basename + "_extracted")

        # Unzip file
        system.LogInfo("Unzipping file %s ..." % current_file)
        success = archive.ExtractArchive(
            archive_file = current_file,
            extract_dir = current_file_extract_dir,
            delete_original = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            system.LogErrorAndQuit("Unable to unzip file %s" % current_file)

        # Deterministically zip file
        system.LogInfo("Deterministically rezipping ...")
        success = archive.CreateArchiveFromFolder(
            archive_file = current_file,
            source_dir = current_file_extract_dir,
            delete_original = True,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            system.LogErrorAndQuit("Unable to rezip file %s" % current_file)

# Start
main()
