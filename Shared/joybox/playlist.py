# Imports
import re

# Local imports
import joybox.config as config
import joybox.strings as strings
import joybox.logger as logger
import joybox.paths as paths

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
                if paths.does_filename_match_extensions(obj_path, extensions):
                    if only_keep_ends:
                        playlist_contents.append(obj)
                    else:
                        playlist_contents.append(obj_path)

    # Check length
    if not allow_empty_lists and len(playlist_contents) == 0:
        return True
    elif not allow_single_lists and len(playlist_contents) == 1:
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

# Disc markers in file names: numbered "(Disc 1)", "(Disk 2)", "(Disc 1 of 3)", lettered "(Disc A)", or labelled "(Game Disc)", "(Bonus Disc)"
disc_marker_pattern = re.compile(r"\((?:(?:disc|disk) (\d+|[a-z])(?: of \d+)?|([^()]+) (?:disc|disk))\)", re.IGNORECASE)

# Get disc sort key: numbered discs first, then lettered, then labelled with the game disc leading
def get_disc_sort_key(filename):
    disc_match = disc_marker_pattern.search(filename)
    if not disc_match:
        return None
    disc_id, disc_label = disc_match.groups()
    if disc_id and disc_id.isdigit():
        return (0, int(disc_id), "")
    if disc_id:
        return (1, 0, disc_id.lower())
    disc_label = disc_label.lower()
    return (2, 0 if disc_label == "game" else 1, disc_label)

# Get disc playlist contents, in disc order, or None when one disc has several images
def get_disc_playlist_contents(source_dir):
    discs = {}
    for obj in paths.get_directory_contents(source_dir):
        if not paths.is_path_file(paths.join_paths(source_dir, obj)):
            continue
        if not paths.does_filename_match_extensions(obj, config.DiscImageFileType.cvalues()):
            continue
        disc_key = get_disc_sort_key(obj)
        if disc_key:
            discs.setdefault(disc_key, []).append(obj)
    if any(len(disc_files) > 1 for disc_files in discs.values()):
        return None
    if len(discs) < 2:
        return []
    return [discs[disc_key][0] for disc_key in sorted(discs)]

# Generate disc playlist, unless the directory already has a playlist
def generate_disc_playlist(
    source_dir,
    playlist_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Keep an existing playlist
    if paths.does_directory_contain_files_by_extensions(path = source_dir, extensions = [".m3u"], recursive = False):
        return True

    # Get numbered discs
    disc_files = get_disc_playlist_contents(source_dir)
    if disc_files is None:
        logger.log_warning("Several disc images share a disc in %s, not creating a playlist" % source_dir)
        return True
    if not disc_files:
        return True

    # Write playlist
    output_file = paths.join_paths(source_dir, playlist_name + ".m3u")
    logger.log_info("Creating disc playlist %s" % output_file)
    return write_playlist(
        output_file = output_file,
        playlist_contents = disc_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
