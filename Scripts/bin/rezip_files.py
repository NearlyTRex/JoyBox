#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import system
import archive
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Rezip files deterministically.")
parser.add_argument("input_path", help="Input path")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()
if not args.input_path:
    parser.print_help()
    system.QuitProgram()

# Check that path exists first
input_path = os.path.realpath(args.input_path)
if not os.path.exists(input_path):
    system.LogErrorAndQuit("Path '%s' does not exist" % args.input_path)

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Rezip zip files
    for file in system.BuildFileListByExtensions(input_path, extensions = [".zip"]):
        current_file = file
        current_file_dir = system.GetFilenameDirectory(current_file)
        current_file_basename = system.GetFilenameBasename(current_file)
        current_file_extract_dir = os.path.join(current_file_dir, current_file_basename + "_extracted")

        # Unzip file
        system.Log("Unzipping file %s ..." % current_file)
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
        system.Log("Deterministically rezipping ...")
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
