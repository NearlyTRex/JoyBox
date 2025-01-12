# Imports
import os, os.path
import sys
import functools

# Local imports
import config
import command
import programs
import system
import environment

# Read playlist file
def ReadPlaylist(
    input_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            system.LogInfo("Reading playlist file %s" % input_file)
        if not pretend_run:
            playlist_contents = []
            with open(input_file, "r", encoding="utf8") as f:
                playlist_contents = []
                for line in f.readlines():
                    playlist_contents.append(line.strip())
            return playlist_contents
        return []
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to read playlist file %s" % input_file)
            system.LogError(e, quit_program = True)
        return []

# Write playlist file
def WritePlaylist(
    output_file,
    playlist_contents = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            system.LogInfo("Writing playlist file %s" % output_file)
        if not pretend_run:
            with open(output_file, "w", encoding="utf8") as f:
                for entry in playlist_contents:
                    f.write(entry + "\n")
        return True
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to write playlist file %s" % output_file)
            system.LogError(e, quit_program = True)
        return False

# Generate playlist file
def GeneratePlaylist(
    source_dir,
    output_file,
    extensions = [],
    recursive = False,
    allow_empty_lists = False,
    allow_single_lists = False,
    only_keep_ends = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Generate playlist contents
    playlist_contents = []
    if recursive:
        for file in system.BuildFileListByExtensions(
            root = source_dir,
            extensions = extensions):
            if only_keep_ends:
                playlist_contents.append(system.GetFilenameFile(file))
            else:
                playlist_contents.append(file)
    else:
        for obj in system.GetDirectoryContents(source_dir):
            obj_path = system.JoinPaths(source_dir, obj)
            if system.IsPathFile(obj_path):
                for extension in extensions:
                    if obj_path.endswith(extension):
                        if only_keep_ends:
                            playlist_contents.append(obj)
                        else:
                            playlist_contents.append(obj_path)

    # Check length
    if allow_empty_lists == False and len(playlist_contents) == 0:
        return True
    elif allow_single_lists == False and len(playlist_contents) == 1:
        return True

    # Write playlist
    return WritePlaylist(
        output_file = output_file,
        playlist_contents = system.SortStringsWithLength(playlist_contents),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Generate tree playlist file
def GenerateTreePlaylist(
    source_dir,
    output_file,
    extensions = [],
    allow_empty_lists = False,
    allow_single_lists = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return GeneratePlaylist(
        source_dir = source_dir,
        output_file = output_file,
        extensions = extensions,
        recursive = True,
        allow_empty_lists = allow_empty_lists,
        allow_single_lists = allow_single_lists,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Generate local playlists
def GenerateLocalPlaylists(
    source_dir,
    extensions = [],
    allow_empty_lists = False,
    allow_single_lists = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check each directory for the requested files
    for input_dir in system.BuildDirectoryList(source_dir):
        if system.DoesDirectoryContainFilesByExtensions(
            path = input_dir,
            extensions = extensions,
            recursive = False):

            # Generate local playlist
            success = GeneratePlaylist(
                source_dir = input_dir,
                output_file = system.JoinPaths(input_dir, system.GetDirectoryName(input_dir) + ".m3u"),
                extensions = extensions,
                recursive = False,
                allow_empty_lists = allow_empty_lists,
                allow_single_lists = allow_single_lists,
                only_keep_ends = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # Must be successful
    return True
