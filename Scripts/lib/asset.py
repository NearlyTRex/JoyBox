# Imports
import os, os.path
import sys

# Local imports
import command
import system
import programs

# Clean exif data
def CleanExifData(
    asset_file,
    verbose = False,
    exit_on_failure = False):

    # Get tool
    exif_tool = None
    if programs.IsToolInstalled("ExifTool"):
        exif_tool = programs.GetToolProgram("ExifTool")
    if not exif_tool:
        system.LogError("ExifTool was not found")
        return False

    # Get clean command
    clean_cmd = [
        exif_tool,
        "-overwrite_original",
        "-All=",
        "-r",
        asset_file
    ]

    # Run clean command
    code = command.RunBlockingCommand(
        cmd = clean_cmd,
        options = command.CommandOptions(
            blocking_processes = [exif_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (code == 0)
