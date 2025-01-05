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
import command
import programs
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Launch pegasus.")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get tool
    pegasus_tool = None
    if programs.IsToolInstalled("Pegasus"):
        pegasus_tool = programs.GetToolProgram("Pegasus")
    if not pegasus_tool:
        system.LogErrorAndQuit("Pegasus was not found")

    # Get launch command
    launch_cmd = [
        pegasus_tool
    ]

    # Get launch options
    launch_options = command.CommandOptions()
    launch_options.cwd = system.GetFilenameDirectory(pegasus_tool)
    launch_options.env = os.environ
    launch_options.env["JOYBOX_LAUNCH_JSON"] = system.JoinPaths(environment.GetScriptsBinDir(), "launch_json" + environment.GetScriptsCommandExtension())

    # Run launch command
    command.RunCheckedCommand(
        cmd = launch_cmd,
        options = launch_options,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Start
main()
