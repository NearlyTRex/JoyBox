# Local imports
from joybox import config
from joybox import sync
from joybox import syncremotes
from joybox import syncdiff
from joybox import synclisting
from joybox import synctransfers
from joybox import rcloneremotes
from joybox import logger
from joybox import paths
from joybox import environment
from joybox import fileops
from joybox import cryption
from joybox import lockerinfo
from joybox import lockerbackend

###########################################################
# Helpers
###########################################################

# Get the default remote locker type (uses primary remote locker)
def get_default_remote_locker():
    return lockerinfo.get_primary_remote_locker_type()

# Check if path is local (exists on local filesystem)
def is_local_path(path):
    local_locker_root = environment.get_locker_root_dir(config.LockerType.LOCAL)
    if local_locker_root and path.startswith(local_locker_root + config.OS_PATHSEP):
        return True
    if paths.does_path_exist(path):
        return True
    return False

# Check if path is remote
def is_remote_path(path):
    return not is_local_path(path)

# Convert to relative path (strips locker root prefix)
def convert_to_relative_path(path, locker_type = None):
    if locker_type is None:
        locker_type = config.LockerType.LOCAL
    locker_root = environment.get_locker_root_dir(locker_type)
    return paths.rebase_file_path(
        path = path,
        old_base_path = locker_root,
        new_base_path = "")

# Rebase a path from a remote locker's root (the default remote when none is given) onto the local locker root; local paths pass through
def convert_to_local_path(path, source_locker_type = None):
    if is_local_path(path):
        return path
    if source_locker_type is None:
        source_locker_type = get_default_remote_locker()
    source_root = environment.get_locker_root_dir(source_locker_type)
    local_root = environment.get_locker_root_dir(config.LockerType.LOCAL)
    return paths.rebase_file_path(
        path = path,
        old_base_path = source_root,
        new_base_path = local_root)

# Check if path exists on locker
def does_path_exist(path, locker_type = None):

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get locker info and backend
    locker_info = lockerinfo.LockerInfo(locker_type)

    # Check if path exists on backend
    backend = lockerbackend.get_backend_for_locker(locker_info)
    rel_path = convert_to_relative_path(path, locker_type)
    return backend.path_exists(rel_path)

# Check if path contains files on locker
def does_path_contain_files(path, locker_type = None):

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get locker info and backend
    locker_info = lockerinfo.LockerInfo(locker_type)

    # Check if path contains files
    backend = lockerbackend.get_backend_for_locker(locker_info)
    rel_path = convert_to_relative_path(path, locker_type)
    return backend.path_contains_files(rel_path)

###########################################################
# Syncing (LOCAL <-> remote, preserves relative paths)
###########################################################

# The destination's path relative to the backend root, or default_rel_path without one
def _get_dest_rel_path(dest_backend, dest, default_rel_path):
    if dest:
        return dest_backend.get_relative_path(dest)
    return default_rel_path

# Sync a relative path between backends, encrypting or decrypting with the locker's
# passphrase when a cryption type is given
def _sync_backends(
    dest_backend,
    src_backend,
    src_rel_path,
    dest_rel_path,
    cryption_type,
    locker_info,
    verbose,
    pretend_run,
    exit_on_failure):
    cryption_options = {}
    if cryption_type:
        cryption_options = {"cryption_type": cryption_type, "passphrase": locker_info.get_passphrase()}
    return dest_backend.sync_from(
        src_backend = src_backend,
        src_rel_path = src_rel_path,
        dest_rel_path = dest_rel_path,
        **cryption_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Sync from a remote locker (the default remote when none is given) to LOCAL, keeping the
# relative path unless dest is given; (success, full local path)
def _sync_remote_to_local(src, dest, locker_type, cryption_type, verbose, pretend_run, exit_on_failure):

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)

    # Get source backend
    src_backend = lockerbackend.get_backend_for_locker(locker_info)
    rel_path = convert_to_relative_path(src, locker_type)

    # Get destination backend (local locker)
    local_info = lockerinfo.LockerInfo(config.LockerType.LOCAL)
    dest_backend = lockerbackend.get_backend_for_locker(local_info)

    # Copy from source to local
    dest_rel_path = _get_dest_rel_path(dest_backend, dest, rel_path)
    success = _sync_backends(
        dest_backend, src_backend, rel_path, dest_rel_path, cryption_type, locker_info,
        verbose, pretend_run, exit_on_failure)
    if not success:
        return (False, "")

    # Return full local path
    local_path = paths.join_paths(dest_backend.get_root_path(), dest_rel_path)
    return (True, local_path)

# Sync from LOCAL to a remote locker (the default remote when none is given), keeping the
# relative path unless dest is given; False when src does not exist
def _sync_local_to_remote(src, dest, locker_type, cryption_type, verbose, pretend_run, exit_on_failure):

    # Check source path exists locally
    if not paths.does_path_exist(src):
        logger.log_error("Path '%s' does not exist" % src)
        return False

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)

    # Get source backend (local)
    local_info = lockerinfo.LockerInfo(config.LockerType.LOCAL)
    src_backend = lockerbackend.get_backend_for_locker(local_info)

    # Get destination backend
    dest_backend = lockerbackend.get_backend_for_locker(locker_info)

    # Copy from local to destination locker
    src_rel_path = src_backend.get_relative_path(src)
    dest_rel_path = _get_dest_rel_path(dest_backend, dest, src_rel_path)
    return _sync_backends(
        dest_backend, src_backend, src_rel_path, dest_rel_path, cryption_type, locker_info,
        verbose, pretend_run, exit_on_failure)

# Sync from remote locker to LOCAL
def sync_from_remote(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return _sync_remote_to_local(src, dest, locker_type, None, verbose, pretend_run, exit_on_failure)

# Sync from LOCAL to remote locker
def sync_to_remote(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return _sync_local_to_remote(src, dest, locker_type, None, verbose, pretend_run, exit_on_failure)

# Sync from encrypted remote locker to LOCAL (with decryption)
def sync_from_remote_decrypted(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return _sync_remote_to_local(src, dest, locker_type, config.CryptionType.DECRYPT, verbose, pretend_run, exit_on_failure)

# Sync from LOCAL to remote locker (with encryption)
def sync_to_remote_encrypted(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return _sync_local_to_remote(src, dest, locker_type, config.CryptionType.ENCRYPT, verbose, pretend_run, exit_on_failure)

###########################################################
# Copying (arbitrary source to locker)
###########################################################

# Copy from arbitrary source path to a locker
def copy_to_locker(
    src,
    dest_rel_path,
    locker_type,
    skip_existing = False,
    skip_identical = False,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source exists
    if not paths.does_path_exist(src):
        logger.log_error("Source path '%s' does not exist" % src)
        return False

    # Get destination locker info and backend
    locker_info = lockerinfo.LockerInfo(locker_type)

    # Copy to destination
    dest_backend = lockerbackend.get_backend_for_locker(locker_info)
    return dest_backend.copy_from(
        src_abs_path = src,
        dest_rel_path = dest_rel_path,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        show_progress = show_progress,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# The passphrase to encrypt an upload with; None for a local-only locker, and None with a
# warning when the locker has none configured
def get_upload_passphrase(locker_info, locker_type):

    # For local-only lockers, skip encryption (just do a plain copy)
    if locker_info.is_local_only():
        return None

    # Encrypt only with a passphrase
    passphrase = locker_info.get_passphrase()
    if not passphrase:
        logger.log_warning("No passphrase configured for locker %s, uploading unencrypted" % locker_type)
        return None
    return passphrase

# Encrypt src into a temporary directory, then upload it to the locker under the encrypted
# name the other locker paths look for
def _copy_encrypted_to_locker(
    src, dest_rel_path, locker_type, passphrase, skip_existing, skip_identical,
    show_progress, verbose, pretend_run, exit_on_failure):
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as temp_dir:
        if not temp_dir:
            logger.log_error("Unable to create temporary directory")
            return False
        encrypted_file = paths.join_paths(temp_dir, cryption.generate_encrypted_filename(paths.get_filename_file(dest_rel_path)))
        success = cryption.encrypt_file(
            src = src,
            passphrase = passphrase,
            output_file = encrypted_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Failed to encrypt file %s" % src)
            return False

        # Upload under the name the other locker paths look for
        encrypted_dest_rel_path = cryption.generate_encrypted_path(dest_rel_path)
        return copy_to_locker(
            src = encrypted_file,
            dest_rel_path = encrypted_dest_rel_path,
            locker_type = locker_type,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Copy from arbitrary source path to a locker (with encryption)
def copy_to_locker_encrypted(
    src,
    dest_rel_path,
    locker_type,
    skip_existing = False,
    skip_identical = False,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source exists
    if not paths.does_path_exist(src):
        logger.log_error("Source path '%s' does not exist" % src)
        return False

    # Get destination locker info and the passphrase to encrypt with
    locker_info = lockerinfo.LockerInfo(locker_type)
    passphrase = get_upload_passphrase(locker_info, locker_type)

    # Without one, just do a plain copy
    if not passphrase:
        return copy_to_locker(
            src = src,
            dest_rel_path = dest_rel_path,
            locker_type = locker_type,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Encrypt source to temp file then upload
    return _copy_encrypted_to_locker(
        src, dest_rel_path, locker_type, passphrase, skip_existing, skip_identical,
        show_progress, verbose, pretend_run, exit_on_failure)

###########################################################
# Backup (copy source to all configured lockers)
###########################################################

# Get all configured lockers
def get_configured_lockers():
    configured = []
    for locker_type in config.LockerType.members():
        if locker_type == config.LockerType.ALL:
            continue
        locker_info = lockerinfo.LockerInfo(locker_type)
        if locker_type == config.LockerType.LOCAL:
            if locker_info.get_mount_path() and paths.does_path_exist(locker_info.get_mount_path()):
                configured.append(locker_type)
            continue
        if locker_type == config.LockerType.EXTERNAL:
            if locker_info.get_mount_path() and paths.does_path_exist(locker_info.get_mount_path()):
                configured.append(locker_type)
            continue
        if not locker_info.get_name():
            continue

        # A remote is defined from its settings, so rclone lists it even with
        # nothing to sign in with; one that cannot sign in can only fail
        if not sync.is_tool_installed():
            logger.log_info("RClone is not installed yet, so locker %s is skipped" % locker_type)
            continue
        if not rcloneremotes.can_sign_in(locker_info.get_name()):
            logger.log_info("Locker %s has nothing to sign in with, so it is skipped" % locker_type)
            continue
        if syncremotes.is_remote_configured(
            remote_name = locker_info.get_name(),
            remote_type = locker_info.get_type()):
            configured.append(locker_type)
    return configured

# None when the backup source exists; otherwise the backup's result, logged: True for a
# pretend run, which never writes what it would back up, else False
def _get_missing_backup_source_result(src, dest_rel_path, pretend_run):
    if paths.does_path_exist(src):
        return None
    if pretend_run:
        logger.log_info("Would back up '%s' to '%s'" % (src, dest_rel_path))
        return True
    logger.log_error("Source path '%s' does not exist" % src)
    return False

# The lockers a backup goes to: every configured one for ALL, else the one given; empty,
# logged, when there is none
def _get_lockers_to_upload(locker_type):
    if locker_type is None:
        logger.log_info("No locker type specified, skipping backup")
        return []
    if locker_type == config.LockerType.ALL:
        lockers_to_upload = get_configured_lockers()
        if not lockers_to_upload:
            logger.log_info("No configured lockers found, skipping backup")
            return []
        logger.log_info("Backing up to all configured lockers: %s" % ", ".join(str(locker) for locker in lockers_to_upload))
        return lockers_to_upload
    return [locker_type]

# Back up src to one locker, encrypted when asked, logging the start and the outcome
def _backup_to_locker(
    src, dest_rel_path, locker, upload_encrypted, show_progress, skip_existing,
    skip_identical, verbose, pretend_run, exit_on_failure):
    logger.log_info("Backing up to locker %s..." % locker)
    if upload_encrypted:
        success = copy_to_locker_encrypted(
            src = src,
            dest_rel_path = dest_rel_path,
            locker_type = locker,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        success = copy_to_locker(
            src = src,
            dest_rel_path = dest_rel_path,
            locker_type = locker,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Backup to %s failed" % locker)
    else:
        logger.log_info("Backup to %s completed" % locker)
    return success

# Backup source to configured lockers
def backup(
    src,
    dest_rel_path,
    locker_type = None,
    delete_afterwards = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    upload_encrypted = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source exists; a pretend run never writes what it would back up
    missing_source_result = _get_missing_backup_source_result(src, dest_rel_path, pretend_run)
    if missing_source_result is not None:
        return missing_source_result

    # Determine which lockers to upload to
    lockers_to_upload = _get_lockers_to_upload(locker_type)
    if not lockers_to_upload:
        return True

    # Upload to each locker directly from source
    all_success = True
    for locker in lockers_to_upload:
        success = _backup_to_locker(
            src, dest_rel_path, locker, upload_encrypted, show_progress, skip_existing,
            skip_identical, verbose, pretend_run, exit_on_failure)
        if not success and exit_on_failure:
            return False
        all_success = all_success and success

    # Delete source afterwards if requested
    if delete_afterwards and all_success:
        fileops.remove_file_or_directory(src, verbose = verbose, pretend_run = pretend_run)

    # Should be successful
    logger.log_info("Backup completed successfully")
    return all_success

###########################################################
# Remote actions (the local locker against a remote locker)
###########################################################

# Actions that need the local locker's path to exist
LOCAL_PATH_ACTIONS = [
    config.RemoteActionType.DOWNLOAD,
    config.RemoteActionType.UPLOAD,
    config.RemoteActionType.PULL,
    config.RemoteActionType.PUSH,
    config.RemoteActionType.MERGE,
    config.RemoteActionType.DIFF,
    config.RemoteActionType.DIFFSYNC,
]

# Quit when an action needs the local locker path and it is unset or missing
def _check_local_path_for_action(action, local_path):
    if action not in LOCAL_PATH_ACTIONS:
        return
    if not local_path:
        logger.log_error("Action '%s' requires a local path, but none is configured for the Local locker" % (
            action), quit_program = True)
    if not paths.does_path_exist(local_path):
        logger.log_error("Action '%s' requires the local locker path to exist: %s" % (
            action, local_path), quit_program = True)

# The excludes for a remote action: the comma-separated patterns given, else the locker's excluded dirs
def get_remote_action_excludes(excludes, locker_info):
    if excludes:
        return [e.strip() for e in excludes.split(",") if e.strip()]
    return locker_info.get_excluded_dirs()

# The remote, local and mount paths, mount flags and excludes a remote action on a locker
# works with; quits when the locker has no remote or the action's local path is missing
def get_remote_action_target(action, locker_type, excludes = ""):
    locker_info = lockerinfo.LockerInfo(locker_type)
    if locker_info.is_local_only():
        logger.log_error("Locker '%s' is not a remote locker" % locker_type, quit_program = True)
    target = {
        "remote_type": locker_info.get_type(),
        "remote_name": locker_info.get_name(),
        "remote_path": locker_info.get_remote_path(),
        "local_path": lockerinfo.LockerInfo(config.LockerType.LOCAL).get_mount_path(),
        "mount_path": locker_info.get_mount_path(),
        "mount_flags": locker_info.get_mount_flags()}
    _check_local_path_for_action(action, target["local_path"])
    target["excludes"] = get_remote_action_excludes(excludes, locker_info)
    return target

# Preview lines for a remote action target, one for each of its local, remote and mount paths that is set
def get_remote_action_preview(target):
    details = []
    if target["local_path"]:
        details.append("Local: %s" % target["local_path"])
    if target["remote_path"]:
        details.append("Remote: %s:%s" % (target["remote_name"], target["remote_path"]))
    if target["mount_path"]:
        details.append("Mount: %s" % target["mount_path"])
    return details

# The transfer functions between the local locker and a remote, by the action that runs each
def _get_transfer_functions():
    return {
        config.RemoteActionType.DOWNLOAD: synctransfers.download_files_from_remote,
        config.RemoteActionType.UPLOAD: synctransfers.upload_files_to_remote,
        config.RemoteActionType.PULL: sync.pull_files_from_remote,
        config.RemoteActionType.PUSH: sync.push_files_to_remote,
        config.RemoteActionType.MERGE: sync.merge_files_both_ways,
    }

# Run a transfer action between the target's local path and its remote; Merge also takes resync
def _run_transfer_action(action, remote, target, resync, interactive, flags):
    transfer = {"local_path": target["local_path"], "excludes": target["excludes"]}
    if action == config.RemoteActionType.MERGE:
        transfer["resync"] = resync
    return _get_transfer_functions()[action](**remote, **transfer, interactive = interactive, **flags)

# Target excludes plus the recycle folder, which diffs leave out
def _get_diff_excludes(excludes, recycle_folder):
    if recycle_folder:
        return sync.get_excludes_with(excludes, recycle_folder + "/**")
    return list(excludes)

# Diff the target's local path against its remote into the combined, intersected,
# missing-on-source, missing-on-destination and error files of diff_paths
def _run_diff_action(remote, target, diff_paths, quick, recycle_folder, flags):
    combined_path, intersected_path, missing_src_path, missing_dest_path, error_path = diff_paths
    return syncdiff.diff_files(
        **remote,
        local_path = target["local_path"],
        excludes = _get_diff_excludes(target["excludes"], recycle_folder),
        diff_combined_path = combined_path,
        diff_intersected_path = intersected_path,
        diff_missing_src_path = missing_src_path,
        diff_missing_dest_path = missing_dest_path,
        diff_error_path = error_path,
        quick = quick,
        **flags)

# Sync the differences between the target's local path and its remote, from the diff files
# in diff_dir or a fresh diff; remote-only files are recycled when recycle_missing is set
def _run_diffsync_action(remote, target, diff_dir, diff_paths, recycle_missing, recycle_folder, quick, interactive, flags):
    combined_path, intersected_path, missing_src_path, missing_dest_path, _ = diff_paths
    return syncdiff.diff_sync_files(
        **remote,
        local_path = target["local_path"],
        excludes = _get_diff_excludes(target["excludes"], recycle_folder),
        diff_dir = diff_dir,
        diff_combined_file = combined_path,
        diff_intersected_file = intersected_path,
        diff_missing_src_file = missing_src_path,
        diff_missing_dest_file = missing_dest_path,
        recycle_missing = recycle_missing,
        recycle_folder = recycle_folder,
        quick = quick,
        interactive = interactive,
        **flags)

# Mount the target's remote at its mount path with the locker's mount flags
def _run_mount_action(remote, target, flags):
    mount_flags = target["mount_flags"]
    return synclisting.mount_files(
        **remote,
        mount_path = target["mount_path"],
        no_cache = "no_cache" in mount_flags,
        no_checksum = "no_checksum" in mount_flags,
        no_modtime = "no_modtime" in mount_flags,
        no_seek = "no_seek" in mount_flags,
        read_only = "read_only" in mount_flags,
        **flags)

# Run a remote action on a target from get_remote_action_target, returning whether it
# succeeded; diff_paths holds the combined, intersected, missing-on-source,
# missing-on-destination and error file paths, and any action not otherwise named mounts
def run_remote_action(
    action,
    target,
    diff_paths,
    diff_dir = None,
    resync = False,
    interactive = False,
    quick = False,
    recycle_missing = False,
    recycle_folder = ".recycle_bin",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    flags = {"verbose": verbose, "pretend_run": pretend_run, "exit_on_failure": exit_on_failure}
    remote = {"remote_name": target["remote_name"], "remote_type": target["remote_type"]}
    if action == config.RemoteActionType.INIT:
        return syncremotes.setup_remote(**remote, **flags)
    remote["remote_path"] = target["remote_path"]
    if action in _get_transfer_functions():
        return _run_transfer_action(action, remote, target, resync, interactive, flags)
    if action == config.RemoteActionType.DIFF:
        return _run_diff_action(remote, target, diff_paths, quick, recycle_folder, flags)
    if action == config.RemoteActionType.DIFFSYNC:
        return _run_diffsync_action(
            remote, target, diff_dir, diff_paths, recycle_missing, recycle_folder, quick, interactive, flags)
    if action == config.RemoteActionType.EMPTYRECYCLE:
        return sync.empty_recycle_bin(**remote, recycle_folder = recycle_folder, **flags)
    if action == config.RemoteActionType.LIST:
        return synclisting.list_files(**remote, recursive = True, only_directories = False, **flags)
    return _run_mount_action(remote, target, flags)
