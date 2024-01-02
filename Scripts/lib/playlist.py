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

# Read playlist file
def ReadPlaylist(input_file, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Reading playlist file %s" % input_file)
        playlist_contents = []
        with open(input_file, "r", encoding="utf8") as f:
            playlist_contents = f.readlines()
        return playlist_contents
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to read playlist file %s" % input_file)
            system.LogError(e)
            sys.exit(1)
        return []

# Write playlist file
def WritePlaylist(output_file, playlist_contents = [], verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Writing playlist file %s" % output_file)
        with open(output_file, "w", encoding="utf8") as f:
            f.writelines(playlist_contents)
        return True
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to write playlist file %s" % output_file)
            system.LogError(e)
            sys.exit(1)
        return False

# Generate playlist file
def GeneratePlaylist(source_dir, source_format, output_file, verbose = False, exit_on_failure = False):

    # Get tool
    python_tool = None
    if programs.IsToolInstalled("PythonVenvPython"):
        python_tool = programs.GetToolProgram("PythonVenvPython")
    if not python_tool:
        system.LogError("PythonVenvPython was not found")
        return False

    # Get script
    playlist_script = None
    if programs.IsToolInstalled("Mkpl"):
        playlist_script = programs.GetToolProgram("Mkpl")
    if not playlist_script:
        system.LogError("Mkpl was not found")
        return False

    # Get create command
    create_cmd = [
        python_tool,
        playlist_script,
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
