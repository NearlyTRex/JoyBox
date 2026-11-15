# Diffing a local tree against a remote and syncing the differences both ways.

# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import command
from joybox import programs
from joybox import rcloneremotes
from joybox import serialization
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import fileedits
from joybox import sync
from joybox import synctransfers

# Diff files
def diff_files(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    diff_combined_path = None,
    diff_intersected_path = None,
    diff_missing_src_path = None,
    diff_missing_dest_path = None,
    diff_error_path = None,
    quick = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Exclude hidden files/folders (starting with .) from diff operations
    excludes = sync.get_excludes_with(excludes, ".*/**")

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get check command
    check_cmd = [
        rclone_tool,
        "check",
        local_path,
        sync.get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    check_cmd += sync.get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.DIFF)
    check_cmd += sync.get_exclude_flags(excludes)
    if paths.is_path_valid(diff_combined_path):
        check_cmd += ["--combined", diff_combined_path]
    if paths.is_path_valid(diff_intersected_path):
        check_cmd += ["--differ", diff_intersected_path]
    if paths.is_path_valid(diff_missing_src_path):
        check_cmd += ["--missing-on-src", diff_missing_src_path]
    if paths.is_path_valid(diff_missing_dest_path):
        check_cmd += ["--missing-on-dst", diff_missing_dest_path]
    if paths.is_path_valid(diff_error_path):
        check_cmd += ["--error", diff_error_path]
    if quick:
        check_cmd += ["--size-only"]
    if verbose:
        check_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run check command
    command.run_returncode_command(
        cmd = check_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Analyze combined output
    if diff_combined_path and os.path.exists(diff_combined_path):
        count_unchanged = 0
        count_changed = 0
        count_only_dest = 0
        count_only_src = 0
        count_error = 0
        for line in serialization.read_text_lines(diff_combined_path) or []:
            if line.startswith("="):
                count_unchanged += 1
            elif line.startswith("-"):
                count_only_dest += 1
            elif line.startswith("+"):
                count_only_src += 1
            elif line.startswith("*"):
                count_changed += 1
            elif line.startswith("!"):
                count_error += 1
        logger.log_info("Number of unchanged files: %d" % count_unchanged)
        logger.log_info("Number of changed files: %d" % count_changed)
        logger.log_info("Number of files only on %s%s: %d" % (sync.get_remote_raw_type(remote_type), remote_path, count_only_dest))
        logger.log_info("Number of files only on %s: %d" % (local_path, count_only_src))
        logger.log_info("Number of error files: %d" % count_error)

    # Sort diff files
    for diff_path in [diff_combined_path, diff_intersected_path, diff_missing_src_path, diff_missing_dest_path, diff_error_path]:
        if diff_path and os.path.exists(diff_path):
            fileedits.sort_file_contents(
                src = diff_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    return True

# Write a transfer list to a temporary file, tracking it for cleanup
def write_transfer_list(entries, temp_files):
    path_ok, list_path = fileops.create_temporary_file(suffix = ".txt")
    if not path_ok:
        logger.log_error("Failed to create temporary file")
        return None
    temp_files.append(list_path)
    if not serialization.write_text_file(list_path, "\n".join(entries)):
        logger.log_error("Failed to write transfer list %s" % list_path)
        return None
    return list_path

# Read the non-blank lines of a diff file
def read_diff_entries(diff_path):
    if not os.path.exists(diff_path):
        return []
    return [line.strip() for line in serialization.read_text_lines(diff_path) or [] if line.strip()]

# Diff sync files
def diff_sync_files(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    diff_dir = None,
    diff_combined_file = "diff_combined.txt",
    diff_intersected_file = "diff_intersected.txt",
    diff_missing_src_file = "diff_missing_src.txt",
    diff_missing_dest_file = "diff_missing_dest.txt",
    sync_changed = True,
    recycle_missing = False,
    recycle_folder = ".recycle_bin",
    quick = False,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Without a diff directory, generate the diffs into a temporary one
    generate_diffs = not diff_dir
    if generate_diffs:
        success, diff_dir = fileops.create_temporary_directory()
        if not success:
            logger.log_error("Failed to create diff directory")
            return False
    temp_files = []
    try:
        return run_diff_sync(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            diff_dir = diff_dir,
            generate_diffs = generate_diffs,
            diff_combined_file = diff_combined_file,
            diff_intersected_file = diff_intersected_file,
            diff_missing_src_file = diff_missing_src_file,
            diff_missing_dest_file = diff_missing_dest_file,
            sync_changed = sync_changed,
            recycle_missing = recycle_missing,
            recycle_folder = recycle_folder,
            quick = quick,
            interactive = interactive,
            temp_files = temp_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    finally:
        for temp_file in temp_files:
            fileops.remove_file(temp_file, exit_on_failure = False)
        if generate_diffs:
            fileops.remove_directory(diff_dir, exit_on_failure = False)

# Diff sync files within a prepared diff directory
def run_diff_sync(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes,
    diff_dir,
    generate_diffs,
    diff_combined_file,
    diff_intersected_file,
    diff_missing_src_file,
    diff_missing_dest_file,
    sync_changed,
    recycle_missing,
    recycle_folder,
    quick,
    interactive,
    temp_files,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check diff directory
    if not paths.does_path_exist(diff_dir):
        logger.log_error("Diff directory was invalid")
        return False

    # Exclude hidden files/folders (starting with .) from diff operations
    excludes = sync.get_excludes_with(excludes, ".*/**")

    # Exclude recycle folder from diff operations
    if recycle_folder:
        excludes = sync.get_excludes_with(excludes, recycle_folder + "/**")

    # Setup diff file paths
    diff_combined_path = os.path.join(diff_dir, diff_combined_file)
    diff_intersected_path = os.path.join(diff_dir, diff_intersected_file)
    diff_missing_src_path = os.path.join(diff_dir, diff_missing_src_file)
    diff_missing_dest_path = os.path.join(diff_dir, diff_missing_dest_file)

    # Diff files if necessary
    if generate_diffs:
        logger.log_info("Running diff to identify file differences...")
        diff_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            excludes = excludes,
            diff_combined_path = diff_combined_path,
            diff_intersected_path = diff_intersected_path,
            diff_missing_src_path = diff_missing_src_path,
            diff_missing_dest_path = diff_missing_dest_path,
            quick = quick,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read files missing on dest (upload), missing on src (download), and changed on both
    files_to_upload = read_diff_entries(diff_missing_dest_path)
    files_to_download = read_diff_entries(diff_missing_src_path)
    changed_files = read_diff_entries(diff_intersected_path) if sync_changed else []

    # Log file change
    logger.log_info("Files to upload (missing on remote): %d" % len(files_to_upload))
    logger.log_info("Files to download (missing on local): %d" % len(files_to_download))
    logger.log_info("Files changed (differ on both): %d" % len(changed_files))

    # Handle changed files by comparing modification times
    if changed_files:
        logger.log_info("Comparing modification times for changed files...")
        changed_to_upload = []
        changed_to_download = []
        for file_path in changed_files:
            local_file = os.path.join(local_path, file_path)
            remote_file_path = os.path.join(remote_path, file_path).replace("\\", "/")

            # Get local modtime
            local_mtime = paths.get_file_mod_time(local_file)

            # Get remote modtime
            remote_mtime = sync.get_path_mod_time(
                remote_name = remote_name,
                remote_type = remote_type,
                remote_path = remote_file_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not local_mtime or not remote_mtime:
                if verbose:
                    logger.log_warning("Could not get modtime for: %s" % file_path)
                continue

            # Add to changes lists
            if local_mtime > remote_mtime:
                if verbose:
                    logger.log_info("Local is newer: %s" % file_path)
                changed_to_upload.append(file_path)
            elif remote_mtime > local_mtime:
                if verbose:
                    logger.log_info("Remote is newer: %s" % file_path)
                changed_to_download.append(file_path)

        # Add changed files to upload/download lists
        logger.log_info("Changed files to upload (local newer): %d" % len(changed_to_upload))
        logger.log_info("Changed files to download (remote newer): %d" % len(changed_to_download))
        files_to_upload.extend(changed_to_upload)
        files_to_download.extend(changed_to_download)

    # Upload files
    if files_to_upload:
        upload_list_path = write_transfer_list(files_to_upload, temp_files)
        if not upload_list_path:
            return False
        logger.log_info("Uploading %d files to remote..." % len(files_to_upload))
        if not synctransfers.upload_files_to_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            files_from = upload_list_path,
            interactive = interactive,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            return False

    # Download or recycle files
    if files_to_download:
        transfer_list_path = write_transfer_list(files_to_download, temp_files)
        if not transfer_list_path:
            return False
        if recycle_missing:
            logger.log_info("Recycling %d files on remote (moving to %s)..." % (len(files_to_download), recycle_folder))
            if not sync.recycle_files_on_remote(
                remote_name = remote_name,
                remote_type = remote_type,
                remote_path = remote_path,
                files_from = transfer_list_path,
                recycle_folder = recycle_folder,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False
        else:
            logger.log_info("Downloading %d files from remote..." % len(files_to_download))
            if not synctransfers.download_files_from_remote(
                remote_name = remote_name,
                remote_type = remote_type,
                remote_path = remote_path,
                local_path = local_path,
                files_from = transfer_list_path,
                interactive = interactive,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False

    # Done
    logger.log_info("DiffSync complete!")
    return True
