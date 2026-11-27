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

# Copy contents
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
    if not pretend_run and not paths.does_path_exist(src, case_sensitive_paths):
        logger.log_error("Source %s does not exist, cannot copy" % src)
        if exit_on_failure:
            runtime.quit_program()
        return False
    file_list = paths.build_file_list(
        root = src,
        use_relative_paths = True,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs)
    per_file_exit = exit_on_failure and not skip_on_error
    failed_count = 0
    for file in file_list:
        input_file = os.path.join(src, file)
        output_file = os.path.join(dest, file)
        output_dir = os.path.dirname(output_file)
        success = fileops.make_directory(
            src = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(input_file, None, error_log_path, verbose, pretend_run)
                continue
            return False
        success = fileops.transfer_file(
            src = input_file,
            dest = output_file,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(input_file, output_file, error_log_path, verbose, pretend_run)
                continue
            return False
    if skip_on_error and failed_count > 0:
        logger.log_warning("copy_contents: %d file(s) skipped due to errors%s" % (
            failed_count,
            (" (logged to %s)" % error_log_path) if error_log_path else ""))
    return True

# Move contents
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
    if not pretend_run and not paths.does_path_exist(src, case_sensitive_paths):
        logger.log_error("Source %s does not exist, cannot move" % src)
        if exit_on_failure:
            runtime.quit_program()
        return False
    file_list = paths.build_file_list(
        root = src,
        use_relative_paths = True,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs)
    per_file_exit = exit_on_failure and not skip_on_error
    failed_count = 0
    for file in file_list:
        input_file = os.path.join(src, file)
        output_file = os.path.join(dest, file)
        output_dir = os.path.dirname(output_file)
        success = fileops.make_directory(
            src = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(input_file, None, error_log_path, verbose, pretend_run)
                continue
            return False
        success = fileops.transfer_file(
            src = input_file,
            dest = output_file,
            delete_afterwards = True,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(input_file, output_file, error_log_path, verbose, pretend_run)
                continue
            return False
    if skip_on_error and failed_count > 0:
        logger.log_warning("move_contents: %d file(s) skipped due to errors%s" % (
            failed_count,
            (" (logged to %s)" % error_log_path) if error_log_path else ""))
    return True

# Copy globbed files
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
    glob_source_dir = paths.get_filename_directory(glob_pattern)
    glob_files = paths.convert_file_list_to_relative_paths(
        file_list = glob.glob(glob_pattern),
        base_dir = glob_source_dir)
    per_file_exit = exit_on_failure and not skip_on_error
    failed_count = 0
    for glob_file in glob_files:
        src_path = os.path.join(glob_source_dir, glob_file)
        dest_path = os.path.join(dest_dir, glob_file)
        success = fileops.make_directory(
            src = os.path.join(dest_dir, paths.get_filename_directory(glob_file)),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(src_path, None, error_log_path, verbose, pretend_run)
                continue
            return False
        success = fileops.transfer_file(
            src = src_path,
            dest = dest_path,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(src_path, dest_path, error_log_path, verbose, pretend_run)
                continue
            return False
    if skip_on_error and failed_count > 0:
        logger.log_warning("copy_globbed_files: %d file(s) skipped due to errors%s" % (
            failed_count,
            (" (logged to %s)" % error_log_path) if error_log_path else ""))
    return True

# Move globbed files
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
    glob_source_dir = paths.get_filename_directory(glob_pattern)
    glob_files = paths.convert_file_list_to_relative_paths(
        file_list = glob.glob(glob_pattern),
        base_dir = glob_source_dir)
    per_file_exit = exit_on_failure and not skip_on_error
    failed_count = 0
    for glob_file in glob_files:
        src_path = os.path.join(glob_source_dir, glob_file)
        dest_path = os.path.join(dest_dir, glob_file)
        success = fileops.make_directory(
            src = os.path.join(dest_dir, paths.get_filename_directory(glob_file)),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(src_path, None, error_log_path, verbose, pretend_run)
                continue
            return False
        success = fileops.transfer_file(
            src = src_path,
            dest = dest_path,
            delete_afterwards = True,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(src_path, dest_path, error_log_path, verbose, pretend_run)
                continue
            return False
    if skip_on_error and failed_count > 0:
        logger.log_warning("move_globbed_files: %d file(s) skipped due to errors%s" % (
            failed_count,
            (" (logged to %s)" % error_log_path) if error_log_path else ""))
    return True

###########################################################
# Smart copy/move utilities
###########################################################

# Smart copy
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
    success = fileops.make_directory(
        src = paths.get_filename_directory(dest),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    if config.TOKEN_GLOB in paths.get_filename_basename(src):
        return copy_globbed_files(
            glob_pattern = src,
            dest_dir = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            skip_on_error = skip_on_error,
            error_log_path = error_log_path,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if os.path.isdir(src):
        return copy_contents(
            src = src,
            dest = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            skip_on_error = skip_on_error,
            error_log_path = error_log_path,
            case_sensitive_paths = case_sensitive_paths,
            ignore_symlinks = ignore_symlinks,
            follow_symlink_dirs = follow_symlink_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return fileops.transfer_file(
        src = src,
        dest = dest,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        skip_on_error = skip_on_error,
        error_log_path = error_log_path,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Smart move
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
    success = fileops.make_directory(
        src = paths.get_filename_directory(dest),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    if config.TOKEN_GLOB in paths.get_filename_basename(src):
        return move_globbed_files(
            glob_pattern = src,
            dest_dir = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            skip_on_error = skip_on_error,
            error_log_path = error_log_path,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if os.path.isdir(src):
        return move_contents(
            src = src,
            dest = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            skip_on_error = skip_on_error,
            error_log_path = error_log_path,
            case_sensitive_paths = case_sensitive_paths,
            ignore_symlinks = ignore_symlinks,
            follow_symlink_dirs = follow_symlink_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return fileops.transfer_file(
        src = src,
        dest = dest,
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

# Smart transfer
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
    if delete_afterwards:
        return smart_move(
            src = src,
            dest = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            skip_on_error = skip_on_error,
            error_log_path = error_log_path,
            case_sensitive_paths = case_sensitive_paths,
            ignore_symlinks = ignore_symlinks,
            follow_symlink_dirs = follow_symlink_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return smart_copy(
        src = src,
        dest = dest,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        skip_on_error = skip_on_error,
        error_log_path = error_log_path,
        case_sensitive_paths = case_sensitive_paths,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################
# Sync utilities
###########################################################

# Sync contents
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

# Sync data
def sync_data(data_src, data_dest, verbose = False, pretend_run = False, exit_on_failure = False):
    is_glob_src = config.TOKEN_GLOB in paths.get_filename_basename(data_src)
    is_glob_dest = config.TOKEN_GLOB in paths.get_filename_basename(data_dest)
    if is_glob_src and is_glob_dest:
        return copy_globbed_files(
            glob_pattern = data_src,
            dest_dir = os.path.dirname(data_dest),
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
