#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import collection
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Clean hash files.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Show preview
    if not args.no_preview:
        details = [environment.GetGameHashesMetadataRootDir()]
        if not system.PromptForPreview("Clean game hash files (sort entries)", details):
            system.LogWarning("Operation cancelled by user")
            return

    # Sort hash files
    success = collection.SortAllHashFiles(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Sort of hash file failed!", quit_program = True)

# Start
if __name__ == "__main__":
    system.RunMain(main)
