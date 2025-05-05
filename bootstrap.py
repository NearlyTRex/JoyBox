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
import configuration
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
parser.add_argument(
    "-s", "--server_index",
    type = int,
    help = "Server index to use")
parser.add_argument("-v", "--verbose", action = "store_true", help = "Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action = "store_true", help = "Enable pretend run mode")
parser.add_argument("-x", "--exit_on_failure", action = "store_true", help = "Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Check arguments
is_local_ubuntu = args.type == constants.EnvironmentType.LOCAL_UBUNTU
is_remote_ubuntu = args.type == constants.EnvironmentType.REMOTE_UBUNTU
is_server_index = isinstance(args.server_index, int) and args.server_index >= 0
if is_remote_ubuntu and not is_server_index:
    util.LogErrorAndQuit("No server specified for remote machine")

# Main
def main():

    # Setup logging
    util.SetupLogging()

    # Get config file
    config_file = os.path.realpath(args.config_file)
    if not os.path.exists(config_file):
        util.LogErrorAndQuit(f"Config file '{config_file}' does not exist")

    # Create environment options
    environment_options = {
        "config": configuration.Configuration(
            src = config_file),
        "flags": util.RunFlags(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure),
        "options": util.RunOptions()
    }

    # Update environment options
    if is_remote_ubuntu:
        environment_options["options"].SetShell(True)
        if is_server_index:
            environment_options["ssh_host"] = config_contents.get("UserData.Servers", {}).get(f"server_{args.server_index}_host")
            environment_options["ssh_port"] = config_contents.get("UserData.Servers", {}).get(f"server_{args.server_index}_port")
            environment_options["ssh_user"] = config_contents.get("UserData.Servers", {}).get(f"server_{args.server_index}_user")
            environment_options["ssh_password"] = config_contents.get("UserData.Servers", {}).get(f"server_{args.server_index}_pass")

    # Create environment runner
    environment_runner = None
    if args.type == constants.EnvironmentType.LOCAL_UBUNTU:
        environment_runner = environments.LocalUbuntu(**environment_options)
    elif args.type == constants.EnvironmentType.REMOTE_UBUNTU:
        environment_runner = environments.RemoteUbuntu(**environment_options)
    if not environment_runner:
        raise Exception("No environment runner could be found")

    # Dispatch action
    if args.action == "setup":
        environment_runner.Setup()
    elif args.action == "teardown":
        environment_runner.Teardown()

# Start
if __name__ == "__main__":
    main()
