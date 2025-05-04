#!/usr/bin/env python3

# Imports
import os
import sys
import argparse

# Custom imports
bootstrap_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "Bootstrap"))
sys.path.append(bootstrap_folder)
import connection
import constants
import settings
import environments
import util

# Set up arguments
parser = argparse.ArgumentParser(description="Environment bootstrap script.")
parser.add_argument(
    "-a", "--action",
    choices = ["setup", "teardown"],
    required = True,
    help = "Action to perform")
parser.add_argument(
    "-t", "--type",
    type = constants.EnvironmentType,
    choices = list(constants.EnvironmentType),
    required = True,
    help = "Environment type")
parser.add_argument(
    "-c", "--config_file",
    default = os.path.join(".", constants.DEFAULT_CONFIG_FILE),
    help = "Path to config file")
parser.add_argument("-v", "--verbose", action = "store_true", help = "Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action = "store_true", help = "Enable pretend run mode")
parser.add_argument("-x", "--exit_on_failure", action = "store_true", help = "Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Main
def main():

    # Setup logging
    util.SetupLogging()

    # Get config file
    config_file = os.path.realpath(args.config_file)
    if not os.path.exists(config_file):
        util.LogErrorAndQuit(f"Config file '{config_file}' does not exist")

    # Load config file
    config_contents = util.InitializeConfigFile(config_file)
    if not isinstance(config_contents, dict):
        util.LogErrorAndQuit(f"Unable to read config data from {config_file}")

    # Create environment options
    environment_options = {
        "config": config_contents,
        "flags": util.RunFlags(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
    }

    # Create environment runner
    environment_runner = None
    if args.type == constants.EnvironmentType.LOCAL_UBUNTU:
        environment_runner = environments.LocalUbuntu(**environment_options)
    if not environment_runner:
        raise ValueError("No environment runner could be found")

    # Dispatch action
    if args.action == "setup":
        environment_runner.Setup()
    elif args.action == "teardown":
        environment_runner.Teardown()

# Start
if __name__ == "__main__":
    main()
