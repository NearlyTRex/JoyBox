# Diffing a local tree against a remote and syncing the differences both ways.

# Imports
import os
import os.path
import contextlib

# Local imports
from joybox import config
from joybox import programs
from joybox import serialization
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import fileedits
from joybox import sync
from joybox import synctransfers

# rclone check's flags for the diff files it writes: combined, intersected, missing on the
# source, missing on the destination, and errors
DIFF_OUTPUT_FLAGS = ["--combined", "--differ", "--missing-on-src", "--missing-on-dst", "--error"]

# Get the flags that have rclone check write each diff file given, in the order diff_files takes them
def get_diff_output_flags(diff_paths):
    flags = []
    for flag, diff_path in zip(DIFF_OUTPUT_FLAGS, diff_paths, strict = True):
        if paths.is_path_valid(diff_path):
            flags += [flag, diff_path]
    return flags

# Log how many files a combined diff file marks unchanged, changed, on one side only, or in error
def log_diff_counts(diff_combined_path, remote_type, remote_path, local_path):
    counts = {marker: 0 for marker in "=*-+!"}
    for line in serialization.read_text_lines(diff_combined_path) or []:
        if line[:1] in counts:
            counts[line[:1]] += 1
    logger.log_info("Number of unchanged files: %d" % counts["="])
    logger.log_info("Number of changed files: %d" % counts["*"])
    logger.log_info("Number of files only on %s%s: %d" % (sync.get_remote_raw_type(remote_type), remote_path, counts["-"]))
    logger.log_info("Number of files only on %s: %d" % (local_path, counts["+"]))
    logger.log_info("Number of error files: %d" % counts["!"])

# Report a finished diff: the combined diff file's counts, and every diff file written sorted
def report_diff(diff_paths, remote_type, remote_path, local_path, verbose, pretend_run, exit_on_failure):
    if diff_paths[0] and os.path.exists(diff_paths[0]):
        log_diff_counts(diff_paths[0], remote_type, remote_path, local_path)
    for diff_path in diff_paths:
        if diff_path and os.path.exists(diff_path):
            fileedits.sort_file_contents(
                src = diff_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

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
    rclone_tool = programs.find_tool_program("RClone")
    if not rclone_tool:
        return False

    # Run check, leaving out hidden files and folders and writing the diff files asked for
    diff_paths = [diff_combined_path, diff_intersected_path, diff_missing_src_path, diff_missing_dest_path, diff_error_path]
    check_cmd = [rclone_tool, "check", local_path, sync.get_remote_connection_path(remote_name, remote_type, remote_path)]
    check_cmd += sync.get_common_remote_flags(remote_name, remote_type, config.RemoteActionType.DIFF)
    check_cmd += sync.get_exclude_flags(sync.get_excludes_with(excludes, ".*/**"))
    check_cmd += get_diff_output_flags(diff_paths)
    if quick:
        check_cmd += ["--size-only"]
    check_cmd += sync.get_run_flags(verbose = verbose)
    sync.run_rclone_command(
        check_cmd, [remote_name], verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    report_diff(diff_paths, remote_type, remote_path, local_path, verbose, pretend_run, exit_on_failure)
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

# A directory to diff in, the one given or else a temporary one, and the temporary files made
# while syncing. Yields (directory, whether its diffs need generating, temporary files), the
# directory None when there is none to use, and removes what was temporary afterwards.
@contextlib.contextmanager
def diff_workspace(diff_dir):
    generate_diffs = not diff_dir
    if generate_diffs:
        success, diff_dir = fileops.create_temporary_directory()
        if not success:
            logger.log_error("Failed to create diff directory")
            yield None, False, []
            return
    temp_files = []
    try:
        if not paths.does_path_exist(diff_dir):
            logger.log_error("Diff directory was invalid")
            diff_dir = None
        yield diff_dir, generate_diffs, temp_files
    finally:
        for temp_file in temp_files:
            fileops.remove_file(temp_file, exit_on_failure = False)
        if generate_diffs:
            fileops.remove_directory(diff_dir, exit_on_failure = False)

# Get a diff sync's excludes: hidden files and folders, and the recycle folder when there is one
def get_diff_sync_excludes(excludes, recycle_folder):
    excludes = sync.get_excludes_with(excludes, ".*/**")
    if recycle_folder:
        excludes = sync.get_excludes_with(excludes, recycle_folder + "/**")
    return excludes

# Generate a diff sync's diff files, all but the error file
def generate_sync_diffs(transfer, excludes, diff_paths, quick):
    logger.log_info("Running diff to identify file differences...")
    combined_path, intersected_path, missing_src_path, missing_dest_path = diff_paths
    diff_files(
        **transfer,
        excludes = excludes,
        diff_combined_path = combined_path,
        diff_intersected_path = intersected_path,
        diff_missing_src_path = missing_src_path,
        diff_missing_dest_path = missing_dest_path,
        quick = quick)

# Split changed files by which side is newer, into those to upload and those to download.
# A file without both modification times, or with equal ones, goes neither way.
def compare_changed_files(transfer, changed_files):
    logger.log_info("Comparing modification times for changed files...")
    to_upload, to_download = [], []
    for file_path in changed_files:
        local_mtime = paths.get_file_mod_time(os.path.join(transfer["local_path"], file_path))
        remote_mtime = sync.get_path_mod_time(
            remote_name = transfer["remote_name"],
            remote_type = transfer["remote_type"],
            remote_path = os.path.join(transfer["remote_path"], file_path).replace("\\", "/"),
            verbose = transfer["verbose"],
            pretend_run = transfer["pretend_run"],
            exit_on_failure = transfer["exit_on_failure"])
        if not local_mtime or not remote_mtime:
            if transfer["verbose"]:
                logger.log_warning("Could not get modtime for: %s" % file_path)
            continue
        if local_mtime == remote_mtime:
            continue
        local_newer = local_mtime > remote_mtime
        if transfer["verbose"]:
            logger.log_info("%s is newer: %s" % ("Local" if local_newer else "Remote", file_path))
        (to_upload if local_newer else to_download).append(file_path)
    logger.log_info("Changed files to upload (local newer): %d" % len(to_upload))
    logger.log_info("Changed files to download (remote newer): %d" % len(to_download))
    return to_upload, to_download

# Plan a diff sync from its diff files: files missing on the remote are uploaded, those missing
# locally downloaded, and changed ones, when synced, go whichever way is newer
def plan_diff_sync(transfer, diff_paths, sync_changed):
    _, intersected_path, missing_src_path, missing_dest_path = diff_paths
    files_to_upload = read_diff_entries(missing_dest_path)
    files_to_download = read_diff_entries(missing_src_path)
    changed_files = read_diff_entries(intersected_path) if sync_changed else []
    logger.log_info("Files to upload (missing on remote): %d" % len(files_to_upload))
    logger.log_info("Files to download (missing on local): %d" % len(files_to_download))
    logger.log_info("Files changed (differ on both): %d" % len(changed_files))
    if changed_files:
        changed_to_upload, changed_to_download = compare_changed_files(transfer, changed_files)
        files_to_upload += changed_to_upload
        files_to_download += changed_to_download
    return files_to_upload, files_to_download

# Upload, then download or recycle, the files a diff sync planned, each through a file list
# kept among its temporary files
def run_diff_sync_transfers(transfer, files_to_upload, files_to_download, recycle_missing, recycle_folder, interactive, temp_files):
    if files_to_upload:
        upload_list_path = write_transfer_list(files_to_upload, temp_files)
        if not upload_list_path:
            return False
        logger.log_info("Uploading %d files to remote..." % len(files_to_upload))
        if not synctransfers.upload_files_to_remote(**transfer, files_from = upload_list_path, interactive = interactive):
            return False
    if not files_to_download:
        return True
    transfer_list_path = write_transfer_list(files_to_download, temp_files)
    if not transfer_list_path:
        return False
    if recycle_missing:
        logger.log_info("Recycling %d files on remote (moving to %s)..." % (len(files_to_download), recycle_folder))
        remote = {key: value for key, value in transfer.items() if key != "local_path"}
        return sync.recycle_files_on_remote(**remote, files_from = transfer_list_path, recycle_folder = recycle_folder)
    logger.log_info("Downloading %d files from remote..." % len(files_to_download))
    return synctransfers.download_files_from_remote(**transfer, files_from = transfer_list_path, interactive = interactive)

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
    with diff_workspace(diff_dir) as (diff_dir, generate_diffs, temp_files):
        if not diff_dir:
            return False
        transfer = dict(
            remote_name = remote_name, remote_type = remote_type, remote_path = remote_path, local_path = local_path,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        diff_paths = [os.path.join(diff_dir, name) for name in (
            diff_combined_file, diff_intersected_file, diff_missing_src_file, diff_missing_dest_file)]
        if generate_diffs:
            generate_sync_diffs(transfer, get_diff_sync_excludes(excludes, recycle_folder), diff_paths, quick)
        files_to_upload, files_to_download = plan_diff_sync(transfer, diff_paths, sync_changed)
        if not run_diff_sync_transfers(
            transfer, files_to_upload, files_to_download, recycle_missing, recycle_folder, interactive, temp_files):
            return False
    logger.log_info("DiffSync complete!")
    return True
