#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import command
import programs
import setup
import ini

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get flags
    verbose = ini.GetIniBoolValue("UserData.Flags", "verbose")
    exit_on_failure = ini.GetIniBoolValue("UserData.Flags", "exit_on_failure")

    # Get tool
    pegasus_tool = None
    if programs.IsToolInstalled("Pegasus"):
        pegasus_tool = programs.GetToolProgram("Pegasus")
    if not pegasus_tool:
        system.LogError("Pegasus was not found")
        sys.exit(1)

    # Get launch command
    launch_cmd = [
        pegasus_tool
    ]

    # Get launch options
    launch_options = command.CommandOptions()
    launch_options.cwd = system.GetFilenameDirectory(pegasus_tool)
    launch_options.env = os.environ
    launch_options.env["JOYBOX_LAUNCH_JSON"] = os.path.join(environment.GetScriptsBinDir(), "launch_json" + environment.GetScriptsCommandExtension())

    # Run launch command
    command.RunCheckedCommand(
        cmd = launch_cmd,
        options = launch_options,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Start
main()
