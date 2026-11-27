# Copying, moving and syncing many files at once: directory contents, globbed
# files, or whatever a source path names.

# Imports
import os
import glob

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import runtime
from joybox import fileops

###########################################################
# Bulk copy/move utilities
###########################################################

# False, logged and quitting when exit_on_failure, when a real run's source path is missing
def _require_source(src, case_sensitive_paths, action, pretend_run, exit_on_failure):
    if not pretend_run and not paths.does_path_exist(src, case_sensitive_paths):
        logger.log_error("Source %s does not exist, cannot %s" % (src, action))
        if exit_on_failure:
            runtime.quit_program()
        return False
    return True

# (input file, output file, output directory) for every file under src mirrored into dest
def _content_transfers(src, dest, ignore_symlinks, follow_symlink_dirs):
    file_list = paths.build_file_list(
        root = src,
        use_relative_paths = True,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs)
    for file in file_list:
        input_file = os.path.join(src, file)
        output_file = os.path.join(dest, file)
        yield input_file, output_file, os.path.dirname(output_file)

# (input file, output file, output directory) for every glob match mirrored into dest_dir
def _globbed_transfers(glob_pattern, dest_dir):
    glob_source_dir = paths.get_filename_directory(glob_pattern)
    glob_files = paths.convert_file_list_to_relative_paths(
        file_list = glob.glob(glob_pattern),
        base_dir = glob_source_dir)
    for glob_file in glob_files:
        src_path = os.path.join(glob_source_dir, glob_file)
        dest_path = os.path.join(dest_dir, glob_file)
        yield src_path, dest_path, os.path.join(dest_dir, paths.get_filename_directory(glob_file))

# Create one file's output directory and transfer it; on failure with skip_on_error the
# failure is reported to the error log
def _transfer_listed_file(
    input_file,
    output_file,
    output_dir,
    delete_afterwards,
    show_progress,
    skip_existing,
    skip_identical,
    skip_on_error,
    error_log_path,
    case_sensitive_paths,
    verbose,
    pretend_run,
    per_file_exit):
    success = fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = per_file_exit)
    if not success:
        if skip_on_error:
            fileops.report_fileio_error(input_file, None, error_log_path, verbose, pretend_run)
        return False
    success = fileops.transfer_file(
        src = input_file,
        dest = output_file,
        delete_afterwards = delete_afterwards,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = per_file_exit)
    if not success and skip_on_error:
        fileops.report_fileio_error(input_file, output_file, error_log_path, verbose, pretend_run)
    return success

# Transfer each (input, output, output directory); with skip_on_error, count failures and warn
# about them under the operation's name, else stop with False at the first
def _transfer_file_list(
    operation,
    transfers,
    delete_afterwards,
    show_progress,
    skip_existing,
    skip_identical,
    skip_on_error,
    error_log_path,
    case_sensitive_paths,
    verbose,
    pretend_run,
    exit_on_failure):
    per_file_exit = exit_on_failure and not skip_on_error
    failed_count = 0
    for input_file, output_file, output_dir in transfers:
        success = _transfer_listed_file(
            input_file, output_file, output_dir, delete_afterwards,
            show_progress, skip_existing, skip_identical, skip_on_error, error_log_path,
            case_sensitive_paths, verbose, pretend_run, per_file_exit)
        if success:
            continue
        if not skip_on_error:
            return False
        failed_count += 1
    if skip_on_error and failed_count > 0:
        logger.log_warning("%s: %d file(s) skipped due to errors%s" % (
            operation,
            failed_count,
            (" (logged to %s)" % error_log_path) if error_log_path else ""))
    return True

# Copy every file under src into dest keeping relative paths; with skip_on_error, log failures
# and carry on, else stop at the first; False when src is missing or a file fails
def copy_contents(
    src,
    dest,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not _require_source(src, case_sensitive_paths, "copy", pretend_run, exit_on_failure):
        return False
    return _transfer_file_list(
        operation = "copy_contents",
        transfers = _content_transfers(src, dest, ignore_symlinks, follow_symlink_dirs),
        delete_afterwards = False,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        skip_on_error = skip_on_error,
        error_log_path = error_log_path,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Move every file under src into dest keeping relative paths, leaving src's folders behind;
# with skip_on_error, log failures and carry on; False when src is missing or a file fails
def move_contents(
    src,
    dest,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not _require_source(src, case_sensitive_paths, "move", pretend_run, exit_on_failure):
        return False
    return _transfer_file_list(
        operation = "move_contents",
        transfers = _content_transfers(src, dest, ignore_symlinks, follow_symlink_dirs),
        delete_afterwards = True,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        skip_on_error = skip_on_error,
        error_log_path = error_log_path,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Copy each file the glob matches into dest_dir, keeping its path relative to the glob's folder
def copy_globbed_files(
    glob_pattern,
    dest_dir,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return _transfer_file_list(
        operation = "copy_globbed_files",
        transfers = _globbed_transfers(glob_pattern, dest_dir),
        delete_afterwards = False,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        skip_on_error = skip_on_error,
        error_log_path = error_log_path,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Move each file the glob matches into dest_dir, keeping its path relative to the glob's folder
def move_globbed_files(
    glob_pattern,
    dest_dir,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return _transfer_file_list(
        operation = "move_globbed_files",
        transfers = _globbed_transfers(glob_pattern, dest_dir),
        delete_afterwards = True,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        skip_on_error = skip_on_error,
        error_log_path = error_log_path,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################
# Smart copy/move utilities
###########################################################

# Keyword options every bulk transfer and fileops.transfer_file take alike
def _bulk_options(
    show_progress,
    skip_existing,
    skip_identical,
    skip_on_error,
    error_log_path,
    case_sensitive_paths,
    verbose,
    pretend_run,
    exit_on_failure):
    return {
        "show_progress": show_progress,
        "skip_existing": skip_existing,
        "skip_identical": skip_identical,
        "skip_on_error": skip_on_error,
        "error_log_path": error_log_path,
        "case_sensitive_paths": case_sensitive_paths,
        "verbose": verbose,
        "pretend_run": pretend_run,
        "exit_on_failure": exit_on_failure
    }

# Create dest's parent, then copy or move a glob's matches, a directory's contents or one file
# to dest, picking by what src names
def _smart_transfer_by_kind(src, dest, delete_afterwards, ignore_symlinks, follow_symlink_dirs, options):
    success = fileops.make_directory(
        src = paths.get_filename_directory(dest),
        verbose = options["verbose"],
        pretend_run = options["pretend_run"],
        exit_on_failure = options["exit_on_failure"])
    if not success:
        return False
    if config.TOKEN_GLOB in paths.get_filename_basename(src):
        if delete_afterwards:
            return move_globbed_files(glob_pattern = src, dest_dir = dest, **options)
        return copy_globbed_files(glob_pattern = src, dest_dir = dest, **options)
    if os.path.isdir(src):
        symlink_options = {"ignore_symlinks": ignore_symlinks, "follow_symlink_dirs": follow_symlink_dirs}
        if delete_afterwards:
            return move_contents(src = src, dest = dest, **symlink_options, **options)
        return copy_contents(src = src, dest = dest, **symlink_options, **options)
    if delete_afterwards:
        return fileops.transfer_file(src = src, dest = dest, delete_afterwards = True, **options)
    return fileops.transfer_file(src = src, dest = dest, **options)

# Copy a glob's matches, a directory's contents or one file to dest, picking by what src names
def smart_copy(
    src,
    dest,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    options = _bulk_options(
        show_progress, skip_existing, skip_identical, skip_on_error, error_log_path,
        case_sensitive_paths, verbose, pretend_run, exit_on_failure)
    return _smart_transfer_by_kind(src, dest, False, ignore_symlinks, follow_symlink_dirs, options)

# Move a glob's matches, a directory's contents or one file to dest, picking by what src names
def smart_move(
    src,
    dest,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    options = _bulk_options(
        show_progress, skip_existing, skip_identical, skip_on_error, error_log_path,
        case_sensitive_paths, verbose, pretend_run, exit_on_failure)
    return _smart_transfer_by_kind(src, dest, True, ignore_symlinks, follow_symlink_dirs, options)

# smart_move when delete_afterwards is set, otherwise smart_copy
def smart_transfer(
    src,
    dest,
    delete_afterwards = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    options = _bulk_options(
        show_progress, skip_existing, skip_identical, skip_on_error, error_log_path,
        case_sensitive_paths, verbose, pretend_run, exit_on_failure)
    symlink_options = {"ignore_symlinks": ignore_symlinks, "follow_symlink_dirs": follow_symlink_dirs}
    if delete_afterwards:
        return smart_move(src = src, dest = dest, **symlink_options, **options)
    return smart_copy(src = src, dest = dest, **symlink_options, **options)

###########################################################
# Sync utilities
###########################################################

# Make dest an exact copy of src by emptying it and copying src's contents in
def sync_contents(
    src,
    dest,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not pretend_run and not paths.does_path_exist(src):
        logger.log_error("Source %s does not exist, cannot sync" % src)
        if exit_on_failure:
            runtime.quit_program()
        return False
    success = fileops.make_directory(
        src = dest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    success = fileops.remove_directory_contents(
        src = dest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    return copy_contents(
        src = src,
        dest = dest,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Copy each file a glob matches into a glob destination's folder, or into a plain destination
# treated as a directory and created when missing
def sync_globbed_data(glob_pattern, data_dest, verbose = False, pretend_run = False, exit_on_failure = False):
    dest_dir = data_dest
    if config.TOKEN_GLOB in paths.get_filename_basename(data_dest):
        dest_dir = os.path.dirname(data_dest)
    elif not fileops.make_directory(
        src = dest_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):
        return False
    return copy_globbed_files(
        glob_pattern = glob_pattern,
        dest_dir = dest_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Mirror a source into dest: a glob copies its matches into a glob dest's folder or a dest directory,
# a directory syncs, a file copies; False when the source is none of these
def sync_data(data_src, data_dest, verbose = False, pretend_run = False, exit_on_failure = False):
    if config.TOKEN_GLOB in paths.get_filename_basename(data_src):
        return sync_globbed_data(
            glob_pattern = data_src,
            data_dest = data_dest,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if os.path.isdir(data_src):
        return sync_contents(
            src = data_src,
            dest = data_dest,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if os.path.isfile(data_src):
        return smart_copy(
            src = data_src,
            dest = data_dest,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if exit_on_failure:
        logger.log_error("Source %s does not exist, cannot sync" % data_src)
        runtime.quit_program()
    return False
