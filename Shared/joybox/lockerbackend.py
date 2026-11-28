# Imports
import os
import os.path
import contextlib
import threading
import concurrent.futures
from abc import ABC, abstractmethod

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import filebulk
from joybox import hashutil
from joybox import cryption
from joybox import sync
from joybox import synclisting
from joybox import syncremotes
from joybox import synctransfers
from joybox import serialization
from joybox import environment

###########################################################
# Abstract Base Class
###########################################################

# File operations every locker supports, addressed by paths relative to the locker root
class LockerBackend(ABC):
    def __init__(self, locker_info):
        self.locker_info = locker_info

    # Where the locker's files live: a local folder or an rclone remote path
    @abstractmethod
    def get_root_path(self):
        """Get the root path for this locker"""

    # Relative path to name, dir, hash, size and mtime of every file not excluded; None when the listing fails
    @abstractmethod
    def list_files_with_hashes(
        self,
        excludes = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """List all files with their hashes, or None when the listing failed"""

    # Move a file into the locker's recycle folder rather than deleting it
    @abstractmethod
    def recycle_file(
        self,
        rel_path,
        recycle_folder = ".recycle_bin",
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """Move file to recycle bin instead of deleting"""

    # Bring one file over from another locker, encrypting or decrypting on the way
    @abstractmethod
    def sync_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        cryption_type = None,
        passphrase = None,
        show_progress = True,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """Sync a file from another backend to this one, optionally encrypting/decrypting"""

    # Copy a local file or folder into the locker at a relative path
    @abstractmethod
    def copy_from(
        self,
        src_abs_path,
        dest_rel_path,
        skip_existing = False,
        skip_identical = False,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """Copy from an absolute source path to this backend"""

    # Whether a regular file is at the relative path
    @abstractmethod
    def file_exists(self, rel_path):
        """Check if file exists at relative path"""

    # Whether a file or folder is at the relative path
    @abstractmethod
    def path_exists(self, rel_path):
        """Check if path (file or directory) exists at relative path"""

    # Whether the relative path is a file or a folder holding at least one file
    @abstractmethod
    def path_contains_files(self, rel_path):
        """Check if path contains any files"""

    # Path relative to the locker root; empty for the root itself, unchanged when outside it
    def get_relative_path(self, full_path):
        root = self.get_root_path()
        if not root:
            return full_path
        trimmed_root = root.rstrip(os.sep)
        if full_path in (root, trimmed_root):
            return ""
        if full_path.startswith(trimmed_root + os.sep):
            return full_path[len(trimmed_root) + len(os.sep):]
        return full_path

    # Sync actions one file at a time; returns the destinations that succeeded and those that failed
    def sync_batch_from(
        self,
        src_backend,
        actions,
        cryption_type = None,
        passphrase = None,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        succeeded = []
        failed = []
        for action in actions:
            src_rel = action.get("src", "")
            dest_rel = action.get("dest", src_rel)
            ok = self.sync_from(
                src_backend = src_backend,
                src_rel_path = src_rel,
                dest_rel_path = dest_rel,
                cryption_type = cryption_type,
                passphrase = passphrase,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            (succeeded if ok else failed).append(dest_rel)
        return (succeeded, failed)

    # No-op for lockers without a hash sidecar; always True
    def update_sidecar_from_local(
        self,
        local_root_path,
        excludes = None,
        clear_first = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del local_root_path, excludes, clear_first, verbose, pretend_run, exit_on_failure
        return True

# Relative and full paths of the files under root_path that no exclude pattern matches
def _list_hash_targets(root_path, excludes):
    targets = []
    for rel_path in paths.build_file_list(root_path, use_relative_paths = True):
        if paths.matches_exclude_pattern(rel_path, excludes):
            continue
        full_path = paths.join_paths(root_path, rel_path)
        if not paths.is_path_file(full_path):
            continue
        targets.append((rel_path, full_path))
    return targets

# Hash map entry for a local file: name, folder, MD5 (read-only, so computed even on a pretend run), size and mtime
def _build_hash_entry(rel_path, full_path, exit_on_failure = False):
    return {
        "filename": paths.get_filename_file(rel_path),
        "dir": paths.get_filename_directory(rel_path),
        "hash": hashutil.calculate_file_md5(
            src = full_path,
            verbose = False,
            pretend_run = False,
            exit_on_failure = exit_on_failure),
        "size": paths.get_file_size(full_path),
        "mtime": paths.get_file_mod_time(full_path)
    }

# Call func on each item, on parallel_files threads when there are several of both (hashlib releases the GIL)
def _run_on_threads(func, items, parallel_files):
    if parallel_files and parallel_files > 1 and len(items) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers = parallel_files) as executor:
            list(executor.map(func, items))
    else:
        for item in items:
            func(item)

# Encrypt or decrypt src into output_file with the cryption type's function
def _convert_file(cryption_type, src, output_file, passphrase, verbose = False, pretend_run = False, exit_on_failure = False):
    return cryption.get_cryption_function(cryption_type)(
        src = src,
        passphrase = passphrase,
        output_file = output_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Download a remote locker's file, by its encrypted name when decrypting, to local_path; its path in download_dir, or None on failure
def _download_stored_file(src_backend, src_rel_path, cryption_type, download_dir, local_path, show_progress = True, verbose = False, pretend_run = False, exit_on_failure = False):
    stored_rel_path = src_backend.get_stored_rel_path(src_rel_path) if cryption_type == config.CryptionType.DECRYPT else src_rel_path
    source_file = paths.join_paths(download_dir, paths.get_filename_file(stored_rel_path))
    if not synctransfers.download_files_from_remote(
        remote_name = src_backend.remote_name,
        remote_type = src_backend.remote_type,
        remote_path = paths.join_paths(src_backend.remote_path, stored_rel_path),
        local_path = local_path,
        show_progress = show_progress,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):
        return None
    return source_file

# Download a remote locker's file to dest_full_path, by way of a temp copy that is encrypted or decrypted when converting
def _download_from_remote_locker(src_backend, src_rel_path, dest_full_path, cryption_type, passphrase, show_progress = True, verbose = False, pretend_run = False, exit_on_failure = False):

    # If no cryption needed, download straight to the destination path
    if cryption_type == config.CryptionType.NONE:
        return synctransfers.download_files_from_remote(
            remote_name = src_backend.remote_name,
            remote_type = src_backend.remote_type,
            remote_path = paths.join_paths(src_backend.remote_path, src_rel_path),
            local_path = dest_full_path,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Download to temp, then encrypt/decrypt
    with fileops.temporary_directory(verbose = verbose) as temp_dir:
        if not temp_dir:
            logger.log_error("Failed to create temp directory for sync")
            return False
        temp_file = _download_stored_file(
            src_backend, src_rel_path, cryption_type, temp_dir, temp_dir,
            show_progress = show_progress, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        if temp_file is None:
            return False
        return _convert_file(cryption_type, temp_file, dest_full_path, passphrase, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# Most source bytes staged for one encrypted batch upload, about 4 GiB
ENCRYPTED_BATCH_MAX_BYTES = 4 * 1024 * 1024 * 1024

# Log each action's destination as one a pretend run would encrypt and upload, returning them all
def preview_encrypted_uploads(actions):
    dests = [a.get("dest", a.get("src", "")) for a in actions]
    for dest in dests:
        logger.log_info("Would encrypt and upload: %s" % dest)
    return dests

# Split actions into those keeping their source's relative path and those renaming it
def split_renamed_actions(actions):
    same_name, renamed = [], []
    for action in actions:
        (same_name if action.get("dest", action.get("src", "")) == action.get("src", "") else renamed).append(action)
    return same_name, renamed

# A local copy of a locker's file to convert: the file itself in a local locker, else downloaded
# from the remote into temp_dir, by its encrypted name when decrypting; None on failure
def get_local_source_file(src_backend, src_rel_path, cryption_type, temp_dir, show_progress = True, verbose = False, pretend_run = False, exit_on_failure = False):
    if isinstance(src_backend, LocalBackend):
        return paths.join_paths(src_backend.get_root_path(), src_rel_path)
    download_dir = paths.join_paths(temp_dir, "download")
    return _download_stored_file(
        src_backend, src_rel_path, cryption_type, download_dir, download_dir + os.sep,
        show_progress = show_progress, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# Batches of actions holding at most max_batch_bytes of source files each, and the destinations whose source is missing
def _group_actions_by_size(actions, src_root, max_batch_bytes):
    failed = []
    batches = []
    current = []
    current_bytes = 0
    for action in actions:
        src_full = paths.join_paths(src_root, action.get("src", ""))
        if not paths.is_path_file(src_full):
            logger.log_error("Missing source file: %s" % src_full)
            failed.append(action.get("dest", action.get("src", "")))
            continue
        size = paths.get_file_size(src_full)
        if current and current_bytes + size > max_batch_bytes:
            batches.append(current)
            current = []
            current_bytes = 0
        current.append(action)
        current_bytes += size
    if current:
        batches.append(current)
    return batches, failed

###########################################################
# Local Backend (Local folders and external mounted drives)
###########################################################

# A locker in a local folder or on a mounted external drive, rooted at its mount path
class LocalBackend(LockerBackend):
    def __init__(self, locker_info):
        super().__init__(locker_info)
        self.root_path = locker_info.get_mount_path()

    # The locker's mount path from its settings
    def get_root_path(self):
        return self.root_path

    # MD5, size and mtime of every non-excluded file under the root, hashed on parallel threads even on a pretend run; None when the root is missing
    def list_files_with_hashes(
        self,
        excludes = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False,
        parallel_files = 8):

        # Get excludes
        excludes = [] if excludes is None else excludes

        # Check root path
        hash_map = {}
        if not self.root_path or not paths.does_path_exist(self.root_path):
            logger.log_error("Local path does not exist: %s" % self.root_path)
            return None

        # Build the list of actual files to hash (apply excludes, skip non-files)
        targets = _list_hash_targets(self.root_path, excludes)
        total_files = len(targets)

        # Hash a single file, collecting results under a lock
        if verbose:
            logger.log_info("Building hash map for local path: %s" % self.root_path)
        lock = threading.Lock()
        progress = {"done": 0}
        def hash_one(item):
            rel_path, full_path = item
            entry = _build_hash_entry(rel_path, full_path, exit_on_failure = exit_on_failure)
            with lock:
                hash_map[rel_path] = entry
                progress["done"] += 1
                if verbose and progress["done"] % 100 == 0:
                    logger.log_info("Processed %d/%d files" % (progress["done"], total_files))

        # Hash in parallel
        _run_on_threads(hash_one, targets, parallel_files)
        return hash_map

    # Move a file into the recycle folder at the locker root
    def recycle_file(
        self,
        rel_path,
        recycle_folder = ".recycle_bin",
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return fileops.recycle_file(
            src = paths.join_paths(self.root_path, rel_path),
            recycle_root = self.root_path,
            recycle_folder = recycle_folder,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Download from a remote or copy from a local locker into this folder, converting through a temp file when encrypting or decrypting
    def sync_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        cryption_type = None,
        passphrase = None,
        show_progress = True,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Default cryption type
        if cryption_type is None:
            cryption_type = config.CryptionType.NONE
        if cryption_type not in cryption.CRYPTION_TYPES:
            logger.log_error("Unknown cryption type: %s" % cryption_type)
            return False

        # Get destination path
        dest_full_path = paths.join_paths(self.root_path, dest_rel_path)

        # Handle remote source
        if isinstance(src_backend, RemoteBackend):
            return _download_from_remote_locker(
                src_backend, src_rel_path, dest_full_path, cryption_type, passphrase,
                show_progress = show_progress, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

        # Handle local source: copy directly when no cryption is needed, else encrypt or decrypt
        src_full_path = paths.join_paths(src_backend.get_root_path(), src_rel_path)
        if cryption_type == config.CryptionType.NONE:
            return filebulk.smart_copy(
                src = src_full_path,
                dest = dest_full_path,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        return _convert_file(cryption_type, src_full_path, dest_full_path, passphrase, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Copy a local file or folder into the locker folder, optionally skipping existing or identical files
    def copy_from(
        self,
        src_abs_path,
        dest_rel_path,
        skip_existing = False,
        skip_identical = False,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        dest_full_path = paths.join_paths(self.root_path, dest_rel_path)
        return filebulk.smart_copy(
            src = src_abs_path,
            dest = dest_full_path,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Whether a regular file is at the relative path under the root
    def file_exists(self, rel_path):
        return paths.is_path_file(paths.join_paths(self.root_path, rel_path))

    # Whether anything is at the relative path under the root
    def path_exists(self, rel_path):
        return paths.does_path_exist(paths.join_paths(self.root_path, rel_path))

    # Whether the relative path is a file, or a folder with at least one file beneath it
    def path_contains_files(self, rel_path):
        full_path = paths.join_paths(self.root_path, rel_path)
        if not paths.does_path_exist(full_path):
            return False
        if paths.is_path_file(full_path):
            return True
        file_list = paths.build_file_list(full_path)
        return len(file_list) > 0

###########################################################
# Remote Backend (rclone-based remotes: gdrive, hetzner, etc.)
###########################################################

# A locker on an rclone remote (Google Drive, Hetzner and the like), named and typed by its settings
class RemoteBackend(LockerBackend):
    def __init__(self, locker_info):
        super().__init__(locker_info)
        self.remote_name = locker_info.get_name()
        self.remote_type = locker_info.get_type()
        self.remote_path = locker_info.get_remote_path() or ""

    # The rclone connection path of the locker's remote path
    def get_root_path(self):
        return sync.get_remote_connection_path(
            self.remote_name,
            self.remote_type,
            self.remote_path)

    # The relative path a file is stored under: its encrypted name on an encrypted locker
    def get_stored_rel_path(self, rel_path):
        if not self.locker_info.is_encrypted():
            return rel_path
        dir_rel = paths.get_filename_directory(rel_path)
        enc_name = cryption.generate_encrypted_filename(paths.get_filename_file(rel_path))
        return (paths.join_paths(dir_rel, enc_name) if dir_rel else enc_name).replace("\\", "/")

    # MD5, size and mtime of every non-excluded file, listed by rclone from the remote
    def list_files_with_hashes(
        self,
        excludes = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return synclisting.list_files_with_hashes(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = self.remote_path,
            hash_type = config.HashType.MD5,
            excludes = excludes,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # File hashes as the remote's hash sidecar records them, without listing the remote
    def list_files_with_hashes_from_sidecar(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del pretend_run
        return synctransfers.list_files_with_hashes_from_sidecar(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = self.remote_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Copy a file under its destination name into a temp dir that stack keeps open; the staged path, or None on failure
    def stage_renamed_upload(self, stack, src_full_path, dest_name, verbose = False, pretend_run = False, exit_on_failure = False):
        temp_dir = stack.enter_context(fileops.temporary_directory(verbose = verbose))
        if not temp_dir:
            logger.log_error("Failed to create temp directory for upload to %s" % self.remote_name)
            return None
        upload_path = paths.join_paths(temp_dir, dest_name)
        if not filebulk.smart_copy(
            src = src_full_path,
            dest = upload_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            return None
        return upload_path

    # Upload a local file or folder to a relative path, staging a renamed file under its destination name first
    def upload_local_path(
        self,
        src_full_path,
        dest_rel_path,
        local_root = None,
        skip_existing = False,
        show_progress = True,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # A directory becomes the destination directory, and a file keeping its name
        # goes into the destination's parent, since rclone copies into a directory
        dest_remote_path = paths.join_paths(self.remote_path, dest_rel_path)
        is_directory = paths.is_path_directory(src_full_path)
        dest_name = paths.get_filename_file(dest_rel_path)
        upload_path = src_full_path
        with contextlib.ExitStack() as stack:
            if not is_directory and paths.get_filename_file(src_full_path) != dest_name:
                upload_path = self.stage_renamed_upload(stack, src_full_path, dest_name, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
                if upload_path is None:
                    return False
            return synctransfers.upload_files_to_remote(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = dest_remote_path if is_directory else paths.get_filename_directory(dest_remote_path),
                local_path = upload_path,
                local_root = local_root,
                skip_existing = skip_existing,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Batch uploads from a local locker: one files-from copy for plain files, about 4 GiB staged batches for encrypted ones; other cases go file by file
    def sync_batch_from(
        self,
        src_backend,
        actions,
        cryption_type = None,
        passphrase = None,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Default cryption type
        if cryption_type is None:
            cryption_type = config.CryptionType.NONE

        # Only local-source plain or encrypted batching is optimized; other cases (e.g. decrypt) go file by file
        is_batched_cryption = cryption_type in (config.CryptionType.NONE, config.CryptionType.ENCRYPT)
        if not isinstance(src_backend, LocalBackend) or not actions or not is_batched_cryption:
            return super().sync_batch_from(
                src_backend = src_backend,
                actions = actions,
                cryption_type = cryption_type,
                passphrase = passphrase,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Plain (unencrypted) batch upload via a single --files-from copy
        if cryption_type == config.CryptionType.NONE:
            return self.upload_plain_batch(src_backend, actions, passphrase, show_progress = show_progress, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

        # Encrypted batch upload
        return self.upload_encrypted_batches(src_backend.get_root_path(), actions, passphrase, show_progress = show_progress, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Upload same-named files in one --files-from copy (it keeps source paths) and renamed ones singly; (succeeded, failed)
    def upload_plain_batch(self, src_backend, actions, passphrase = None, show_progress = False, verbose = False, pretend_run = False, exit_on_failure = False):
        same_name, renamed = split_renamed_actions(actions)
        succeeded, failed = super().sync_batch_from(
            src_backend = src_backend,
            actions = renamed,
            cryption_type = config.CryptionType.NONE,
            passphrase = passphrase,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not same_name:
            return (succeeded, failed)
        src_rels = [a.get("src", "") for a in same_name]
        logger.log_info("Uploading %d files to %s (batched)..." % (len(src_rels), self.remote_name))
        if pretend_run:
            for rel in src_rels:
                logger.log_info("Would upload: %s" % rel)
            return (succeeded + src_rels, failed)
        if self.upload_files_from_list(src_backend.get_root_path(), src_rels, show_progress = show_progress, verbose = verbose, exit_on_failure = exit_on_failure):
            return (succeeded + src_rels, failed)
        return (succeeded, failed + src_rels)

    # Upload the files listed relative to src_root with one --files-from copy, leaving the sidecar alone; False on failure
    def upload_files_from_list(self, src_root, src_rels, show_progress = False, verbose = False, exit_on_failure = False):
        files_from_ok, files_from = fileops.create_temporary_file(suffix = ".txt")
        if not files_from_ok:
            logger.log_error("Failed to create temporary file")
            return False
        try:
            ok = serialization.write_text_file(files_from, "\n".join(src_rels))
            if not ok:
                logger.log_error("Failed to write file list %s" % files_from)
                return ok
            return synctransfers.upload_files_to_remote(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = self.remote_path,
                local_path = src_root,
                files_from = files_from,
                update_sidecar = False,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = False,
                exit_on_failure = exit_on_failure)
        finally:
            fileops.remove_file(files_from, exit_on_failure = False)

    # Encrypt and upload in size-bounded batches staged on the roomy cache volume, not a small /tmp; (succeeded, failed)
    def upload_encrypted_batches(self, src_root, actions, passphrase, show_progress = False, verbose = False, pretend_run = False, exit_on_failure = False):
        logger.log_info("Encrypting and uploading %d files to %s (batched)..." % (len(actions), self.remote_name))
        if pretend_run:
            return (preview_encrypted_uploads(actions), [])
        stage_parent = environment.get_cache_root_dir()

        # Group actions into size-bounded batches by source file size
        succeeded = []
        batches, failed = _group_actions_by_size(actions, src_root, ENCRYPTED_BATCH_MAX_BYTES)

        # Stage, encrypt and upload each batch in turn
        for batch in batches:
            batch_succeeded, batch_failed = self.upload_encrypted_batch(
                batch, src_root, stage_parent, passphrase, verbose, pretend_run, exit_on_failure, show_progress = show_progress)
            succeeded.extend(batch_succeeded)
            failed.extend(batch_failed)
        return (succeeded, failed)

    # Encrypt a batch of files into a staging directory mirroring their destinations, and upload
    # it in one go, returning the destinations that succeeded and those that failed
    def upload_encrypted_batch(self, batch, src_root, stage_parent, passphrase, verbose = False, pretend_run = False, exit_on_failure = False, show_progress = True):
        with fileops.temporary_directory(directory = stage_parent, verbose = verbose) as staging:
            if not staging:
                logger.log_error("Failed to create staging directory for encrypted upload")
                return [], [a.get("dest", a.get("src", "")) for a in batch]
            staged, failed = cryption.stage_encrypted_batch(batch, src_root, staging, passphrase, verbose, pretend_run, exit_on_failure)
            if not staged:
                return [], failed
            if synctransfers.upload_files_to_remote(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = self.remote_path,
                local_path = staging,
                update_sidecar = False,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return staged, failed
            return [], failed + staged

    # Rebuild the remote's hash sidecar from the plaintext local copy, optionally clearing it first; False when the clear fails
    def update_sidecar_from_local(
        self,
        local_root_path,
        excludes = None,
        clear_first = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Optionally clear the existing sidecar first (one-time purge of stale entries).
        # Rebuilding on top of a sidecar that could not be cleared would keep the stale ones.
        if clear_first:
            db_path = synctransfers.get_hash_database_path(self.remote_path)
            if sync.does_file_exist(self.remote_name, self.remote_type, db_path, verbose = verbose):
                if not synctransfers.clear_hash_sidecar_files(
                    remote_name = self.remote_name,
                    remote_type = self.remote_type,
                    remote_path = self.remote_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure):
                    logger.log_error("Failed to clear the hash sidecar on %s" % self.remote_name)
                    return False

        # Rebuild the sidecar from authoritative local (plaintext) content
        return synctransfers.upload_hash_sidecar_files(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = self.remote_path,
            local_path = local_root_path,
            local_root = self.remote_path,
            excludes = excludes,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Move a file, by its stored (possibly encrypted) name, into the remote's recycle folder
    def recycle_file(
        self,
        rel_path,
        recycle_folder = ".recycle_bin",
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Create a temporary file list for the recycle operation
        temp_file_ok, temp_file = fileops.create_temporary_file(suffix = ".txt")
        if not temp_file_ok:
            logger.log_error("Failed to create temporary file")
            return False
        try:
            if not serialization.write_text_file(temp_file, self.get_stored_rel_path(rel_path)):
                logger.log_error("Failed to write file list %s" % temp_file)
                return False
            return sync.recycle_files_on_remote(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = self.remote_path,
                files_from = temp_file,
                recycle_folder = recycle_folder,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        finally:
            fileops.remove_file(temp_file, exit_on_failure = False)

    # Copy into the remote from a local or remote locker; plain remote copies stay remote, conversions are staged locally under the destination name
    def sync_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        cryption_type = None,
        passphrase = None,
        show_progress = True,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Default cryption type
        if cryption_type is None:
            cryption_type = config.CryptionType.NONE
        if cryption_type not in cryption.CRYPTION_TYPES:
            logger.log_error("Unknown cryption type: %s" % cryption_type)
            return False
        if not isinstance(src_backend, (LocalBackend, RemoteBackend)):
            logger.log_error("Unsupported source locker: %s" % type(src_backend).__name__)
            return False

        # Plain copies go straight from the source
        if cryption_type == config.CryptionType.NONE:
            return self.copy_plain_from(src_backend, src_rel_path, dest_rel_path, show_progress = show_progress, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

        # Conversions are staged locally first
        return self.upload_converted_from(
            src_backend, src_rel_path, dest_rel_path, cryption_type, passphrase,
            show_progress = show_progress, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Copy a file unconverted: remote to remote without landing locally, or uploaded from a local locker
    def copy_plain_from(self, src_backend, src_rel_path, dest_rel_path, show_progress = True, verbose = False, pretend_run = False, exit_on_failure = False):
        if isinstance(src_backend, RemoteBackend):
            return sync.copy_remote_to_remote(
                src_remote_name = src_backend.remote_name,
                src_remote_type = src_backend.remote_type,
                src_remote_path = paths.join_paths(src_backend.remote_path, src_rel_path),
                dest_remote_name = self.remote_name,
                dest_remote_type = self.remote_type,
                dest_remote_path = paths.join_paths(self.remote_path, dest_rel_path),
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        return self.upload_local_path(
            src_full_path = paths.join_paths(src_backend.get_root_path(), src_rel_path),
            dest_rel_path = dest_rel_path,
            local_root = self.remote_path,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Encrypt or decrypt a local or downloaded copy into a staged file under the destination name, encrypted when encrypting, and upload it
    def upload_converted_from(self, src_backend, src_rel_path, dest_rel_path, cryption_type, passphrase, show_progress = True, verbose = False, pretend_run = False, exit_on_failure = False):
        dest_name = paths.get_filename_file(dest_rel_path)
        if cryption_type == config.CryptionType.ENCRYPT:
            dest_name = cryption.generate_encrypted_filename(dest_name)
        with fileops.temporary_directory(verbose = verbose) as temp_dir:
            if not temp_dir:
                logger.log_error("Failed to create temp directory for sync to %s" % self.remote_name)
                return False
            staged_dir = paths.join_paths(temp_dir, "staged")
            staged_file = paths.join_paths(staged_dir, dest_name)
            fileops.make_directory(src = staged_dir, verbose = verbose, pretend_run = pretend_run)

            # Get a local copy of the source
            source_file = get_local_source_file(
                src_backend, src_rel_path, cryption_type, temp_dir,
                show_progress = show_progress, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
            if source_file is None:
                return False

            # Stage it under the destination name, converting it on the way
            if not _convert_file(cryption_type, source_file, staged_file, passphrase, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                return False

            # Upload the staged file
            return synctransfers.upload_files_to_remote(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = paths.get_filename_directory(paths.join_paths(self.remote_path, dest_rel_path)),
                local_path = staged_file,
                local_root = self.remote_path,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Upload a local file or folder to a relative path; rclone already skips identical files, so skip_identical adds nothing
    def copy_from(
        self,
        src_abs_path,
        dest_rel_path,
        skip_existing = False,
        skip_identical = False,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return self.upload_local_path(
            src_full_path = src_abs_path,
            dest_rel_path = dest_rel_path,
            skip_existing = skip_existing,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Whether a regular file is stored at the relative path on the remote, under its encrypted name on an encrypted locker
    def file_exists(self, rel_path):
        result = sync.run_remote_query(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = paths.join_paths(self.remote_path, self.get_stored_rel_path(rel_path)),
            subcommand = ["lsjson", "--stat"])
        if result is None or result[1] != 0:
            return False
        entry = serialization.parse_json_or_none(result[0])
        return isinstance(entry, dict) and entry.get("IsDir") is False

    # Whether a file or folder exists at the relative path on the remote; an encrypted locker's files are found by stored name
    def path_exists(self, rel_path):
        if self.locker_info.is_encrypted() and self.file_exists(rel_path):
            return True
        full_path = paths.join_paths(self.remote_path, rel_path)
        return sync.does_path_exist(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = full_path)

    # Whether the relative path on the remote holds any files
    def path_contains_files(self, rel_path):
        full_path = paths.join_paths(self.remote_path, rel_path)
        return sync.does_path_contain_files(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = full_path)

###########################################################
# Factory Function
###########################################################

# A remote backend when the locker's rclone remote is configured, otherwise a local one on its mount path
def get_backend_for_locker(locker_info):
    if locker_info.is_local_only():
        return LocalBackend(locker_info)
    remote_name = locker_info.get_name()
    remote_type = locker_info.get_type()
    if remote_name and remote_type and syncremotes.is_remote_configured(remote_name, remote_type):
        return RemoteBackend(locker_info)
    return LocalBackend(locker_info)
