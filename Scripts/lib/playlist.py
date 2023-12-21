# Imports
import os
import os.path
import sys

# Local imports
import config
import command
import programs
import system
import environment

# Generate playlist
def GeneratePlaylist(source_dir, source_format, output_file, verbose = False, exit_on_failure = False):

    # Get tool
    playlist_tool = None
    if programs.IsToolInstalled("Mkpl"):
        playlist_tool = programs.GetToolProgram("Mkpl")
    if not playlist_tool:
        return False

    # Get create command
    create_cmd = [
        programs.GetToolProgram("PythonVenvPython"),
        playlist_tool,
        output_file,
        "-r",
        "-d", source_dir,
        "-i", source_format
    ]

    # Run create command
    command.RunCheckedCommand(
        cmd = create_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Sort playlist
    system.SortFileContents(
        src = output_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_file)
