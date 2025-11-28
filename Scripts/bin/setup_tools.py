#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import arguments
import system
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Setup tools.")
parser.add_boolean_argument(args = ("-e", "--offline"), description = "Enable offline mode")
parser.add_boolean_argument(args = ("-c", "--configure"), description = "Enable configuration mode")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup tools
    setup.SetupTools(
        offline = args.offline,
        configure = args.configure,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
if __name__ == "__main__":
    system.RunMain(main)
