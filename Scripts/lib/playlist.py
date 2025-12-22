# Imports
import os, os.path
import sys
import functools

# Local imports
import config
import command
import programs
import strings
import system
import logger
import paths
import environment

# Read playlist file
def read_playlist(
    input_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Reading playlist file %s" % input_file)
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
            logger.log_error("Unable to read playlist file %s" % input_file)
            logger.log_error(e, quit_program = True)
        return []

# Write playlist file
def write_playlist(
    output_file,
    playlist_contents = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Writing playlist file %s" % output_file)
        if not pretend_run:
            with open(output_file, "w", encoding="utf8") as f:
                for entry in playlist_contents:
                    f.write(entry + "\n")
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to write playlist file %s" % output_file)
            logger.log_error(e, quit_program = True)
        return False

# Generate playlist file
def generate_playlist(
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
        for file in paths.build_file_list_by_extensions(source_dir, extensions = extensions):
            if only_keep_ends:
                playlist_contents.append(paths.get_filename_file(file))
            else:
                playlist_contents.append(file)
    else:
        for obj in paths.get_directory_contents(source_dir):
            obj_path = paths.join_paths(source_dir, obj)
            if paths.is_path_file(obj_path):
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
    return write_playlist(
        output_file = output_file,
        playlist_contents = strings.sort_strings_with_length(playlist_contents),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Generate tree playlist file
def generate_tree_playlist(
    source_dir,
    output_file,
    extensions = [],
    allow_empty_lists = False,
    allow_single_lists = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return generate_playlist(
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
def generate_local_playlists(
    source_dir,
    extensions = [],
    allow_empty_lists = False,
    allow_single_lists = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check each directory for the requested files
    for input_dir in paths.build_directory_list(source_dir):
        if paths.does_directory_contain_files_by_extensions(
            path = input_dir,
            extensions = extensions,
            recursive = False):

            # Generate local playlist
            success = generate_playlist(
                source_dir = input_dir,
                output_file = paths.join_paths(input_dir, paths.get_directory_name(input_dir) + ".m3u"),
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

    # Should be successful
    return True
