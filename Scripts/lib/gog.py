# Imports
import os, os.path
import sys

# Local imports
import command
import programs
import system

# Download game
def DownloadGame(game, output_dir, platform, include, verbose = False, exit_on_failure = False):

    # Get tool
    gog_tool = None
    if programs.IsToolInstalled("LGOGDownloader"):
        gog_tool = programs.GetToolProgram("LGOGDownloader")
    if not gog_tool:
        system.LogError("LGOGDownloader was not found")
        sys.exit(1)

    # Get download command
    download_cmd = [
        gog_tool,
        "--download",
        "--platform=%s" % platform,
        "--include=%s" % include,
        "--directory=%s" % os.path.realpath(output_dir),
        "--game=%s" % game
    ]

    # Run download command
    code = command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            blocking_processes = [gog_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (code == 0)
