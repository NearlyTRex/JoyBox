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

# Generate music playlist
def GenerateMusicPlaylist(source_dir, output_file, verbose = False):

    # Get create command
    create_cmd = [
        "mkpl",
        "-r",
        "-d", source_dir,
        "-f", "mp3",
        output_file
    ]

    # Run create command
    command.RunCheckedCommand(
        cmd = create_cmd,
        verbose = verbose)

    # Sort playlist
    system.SortFileContents(
        path = output_file,
        verbose = verbose,
        exit_on_failure = True)
