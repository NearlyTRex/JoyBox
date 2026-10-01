# Imports
import os
import os.path
import threading
import concurrent.futures
from abc import ABC, abstractmethod

# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths
import joybox.fileops as fileops
import joybox.hashing as hashing
import joybox.cryption as cryption
import joybox.sync as sync
import joybox.serialization as serialization
import joybox.environment as environment

# Cryption types a transfer understands
CRYPTION_TYPES = (
    config.CryptionType.NONE,
    config.CryptionType.ENCRYPT,
    config.CryptionType.DECRYPT,
)

# The function that carries out an encrypt or decrypt
def get_cryption_function(cryption_type):
    if cryption_type == config.CryptionType.ENCRYPT:
        return cryption.encrypt_file
    return cryption.decrypt_file

###########################################################
# Abstract Base Class
###########################################################

class LockerBackend(ABC):
    """Abstract interface for locker file operations"""
    def __init__(self, locker_info):
        self.locker_info = locker_info

    @abstractmethod
    def get_root_path(self):
        """Get the root path for this locker"""

    @abstractmethod
    def list_files_with_hashes(
        self,
        excludes = [],
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """
        List all files with their hashes.
        Returns dict keyed by relative path: {filename, dir, hash, size, mtime},
        or None when the listing failed
        """

    @abstractmethod
    def recycle_file(
        self,
        rel_path,
        recycle_folder = ".recycle_bin",
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """Move file to recycle bin instead of deleting"""

    @abstractmethod
    def sync_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        cryption_type = None,
        passphrase = None,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """Sync a file from another backend to this one, optionally encrypting/decrypting"""

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

    @abstractmethod
    def file_exists(self, rel_path):
        """Check if file exists at relative path"""

    @abstractmethod
    def path_exists(self, rel_path):
        """Check if path (file or directory) exists at relative path"""

    @abstractmethod
    def path_contains_files(self, rel_path):
        """Check if path contains any files"""

    def get_relative_path(self, full_path):
        """Convert a full path to a relative path within this locker"""
        root = self.get_root_path()
        if not root:
            return full_path
        trimmed_root = root.rstrip(os.sep)
        if full_path == root or full_path == trimmed_root:
            return ""
        if full_path.startswith(trimmed_root + os.sep):
            return full_path[len(trimmed_root) + len(os.sep):]
        return full_path

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
            if ok:
                succeeded.append(dest_rel)
            else:
                failed.append(dest_rel)
        return (succeeded, failed)

    def update_sidecar_from_local(
        self,
        local_root_path,
        excludes = [],
        clear_first = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return True

###########################################################
# Local Backend (Local folders and external mounted drives)
###########################################################

class LocalBackend(LockerBackend):
    def __init__(self, locker_info):
        super().__init__(locker_info)
        self.root_path = locker_info.get_mount_path()

    def get_root_path(self):
        return self.root_path

    def list_files_with_hashes(
        self,
        excludes = [],
        parallel_files = 8,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check root path
        hash_map = {}
        if not self.root_path or not paths.does_path_exist(self.root_path):
            logger.log_error("Local path does not exist: %s" % self.root_path)
            return None

        # Build the list of actual files to hash (apply excludes, skip non-files)
        targets = []
        for rel_path in paths.build_file_list(self.root_path, use_relative_paths = True):
            if paths.matches_exclude_pattern(rel_path, excludes):
                continue
            full_path = paths.join_paths(self.root_path, rel_path)
            if not paths.is_path_file(full_path):
                continue
            targets.append((rel_path, full_path))
        total_files = len(targets)

        # Hash a single file (read-only; computed even under pretend_run so the diff and
        # dry runs are accurate). Results are collected under a lock.
        if verbose:
            logger.log_info("Building hash map for local path: %s" % self.root_path)
        lock = threading.Lock()
        progress = {"done": 0}
        def hash_one(item):
            rel_path, full_path = item
            entry = {
                "filename": paths.get_filename_file(rel_path),
                "dir": paths.get_filename_directory(rel_path),
                "hash": hashing.calculate_file_md5(
                    src = full_path,
                    verbose = False,
                    pretend_run = False,
                    exit_on_failure = exit_on_failure),
                "size": paths.get_file_size(full_path),
                "mtime": paths.get_file_mod_time(full_path)
            }
            with lock:
                hash_map[rel_path] = entry
                progress["done"] += 1
                if verbose and progress["done"] % 100 == 0:
                    logger.log_info("Processed %d/%d files" % (progress["done"], total_files))

        # Hash in parallel (hashlib releases the GIL, so threads give real speedup)
        if parallel_files and parallel_files > 1 and total_files > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers = parallel_files) as executor:
                list(executor.map(hash_one, targets))
        else:
            for item in targets:
                hash_one(item)
        return hash_map

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

    def sync_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        cryption_type = None,
        passphrase = None,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Default cryption type
        if cryption_type is None:
            cryption_type = config.CryptionType.NONE
        if cryption_type not in CRYPTION_TYPES:
            logger.log_error("Unknown cryption type: %s" % cryption_type)
            return False

        # Get destination path
        dest_full_path = paths.join_paths(self.root_path, dest_rel_path)

        # Handle remote source
        if isinstance(src_backend, RemoteBackend):

            # If no cryption needed, download straight to the destination path
            if cryption_type == config.CryptionType.NONE:
                return sync.download_files_from_remote(
                    remote_name = src_backend.remote_name,
                    remote_type = src_backend.remote_type,
                    remote_path = paths.join_paths(src_backend.remote_path, src_rel_path),
                    local_path = dest_full_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

            # A file being decrypted is stored under its encrypted name
            stored_rel_path = src_rel_path
            if cryption_type == config.CryptionType.DECRYPT:
                stored_rel_path = src_backend.get_stored_rel_path(src_rel_path)

            # Download to temp, then encrypt/decrypt
            temp_dir_ok, temp_dir = fileops.create_temporary_directory(verbose = verbose)
            if not temp_dir_ok:
                logger.log_error("Failed to create temp directory for sync")
                return False
            temp_file = paths.join_paths(temp_dir, paths.get_filename_file(stored_rel_path))
            try:
                success = sync.download_files_from_remote(
                    remote_name = src_backend.remote_name,
                    remote_type = src_backend.remote_type,
                    remote_path = paths.join_paths(src_backend.remote_path, stored_rel_path),
                    local_path = temp_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False
                return get_cryption_function(cryption_type)(
                    src = temp_file,
                    passphrase = passphrase,
                    output_file = dest_full_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            finally:
                fileops.remove_directory(temp_dir, exit_on_failure = False)

        # Handle local source
        src_full_path = paths.join_paths(src_backend.get_root_path(), src_rel_path)

        # If no cryption needed, copy directly
        if cryption_type == config.CryptionType.NONE:
            return fileops.smart_copy(
                src = src_full_path,
                dest = dest_full_path,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Encrypt or decrypt
        return get_cryption_function(cryption_type)(
            src = src_full_path,
            passphrase = passphrase,
            output_file = dest_full_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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
        return fileops.smart_copy(
            src = src_abs_path,
            dest = dest_full_path,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    def file_exists(self, rel_path):
        return paths.is_path_file(paths.join_paths(self.root_path, rel_path))

    def path_exists(self, rel_path):
        return paths.does_path_exist(paths.join_paths(self.root_path, rel_path))

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

class RemoteBackend(LockerBackend):
    def __init__(self, locker_info):
        super().__init__(locker_info)
        self.remote_name = locker_info.get_name()
        self.remote_type = locker_info.get_type()
        self.remote_path = locker_info.get_remote_path() or ""

    def get_root_path(self):
        return sync.get_remote_connection_path(
            self.remote_name,
            self.remote_type,
            self.remote_path)

    def get_stored_rel_path(self, rel_path):
        """The relative path a file is stored under, which is its encrypted name on an encrypted locker"""
        if not self.locker_info.is_encrypted():
            return rel_path
        dir_rel = paths.get_filename_directory(rel_path)
        enc_name = cryption.generate_encrypted_filename(paths.get_filename_file(rel_path))
        return (paths.join_paths(dir_rel, enc_name) if dir_rel else enc_name).replace("\\", "/")

    def list_files_with_hashes(
        self,
        excludes = [],
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return sync.list_files_with_hashes(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = self.remote_path,
            hash_type = config.HashType.MD5,
            excludes = excludes,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    def list_files_with_hashes_from_sidecar(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return sync.list_files_with_hashes_from_sidecar(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = self.remote_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    def upload_local_path(
        self,
        src_full_path,
        dest_rel_path,
        local_root = None,
        skip_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # A directory becomes the destination directory, and a file keeping its name
        # goes into the destination's parent, since rclone copies into a directory
        dest_remote_path = paths.join_paths(self.remote_path, dest_rel_path)
        is_directory = paths.is_path_directory(src_full_path)
        dest_name = paths.get_filename_file(dest_rel_path)
        upload_path = src_full_path
        temp_dir = None
        if not is_directory and paths.get_filename_file(src_full_path) != dest_name:

            # A renamed file is staged under its destination name first
            temp_dir_ok, temp_dir = fileops.create_temporary_directory(verbose = verbose)
            if not temp_dir_ok:
                logger.log_error("Failed to create temp directory for upload to %s" % self.remote_name)
                return False
            upload_path = paths.join_paths(temp_dir, dest_name)
        try:
            if temp_dir and not fileops.smart_copy(
                src = src_full_path,
                dest = upload_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False
            return sync.upload_files_to_remote(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = dest_remote_path if is_directory else paths.get_filename_directory(dest_remote_path),
                local_path = upload_path,
                local_root = local_root,
                skip_existing = skip_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        finally:
            if temp_dir:
                fileops.remove_directory(temp_dir, exit_on_failure = False)

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

        # Only local-source batching is optimized; fall back otherwise
        if not isinstance(src_backend, LocalBackend) or not actions:
            return super().sync_batch_from(
                src_backend = src_backend,
                actions = actions,
                cryption_type = cryption_type,
                passphrase = passphrase,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        src_root = src_backend.get_root_path()

        # Plain (unencrypted) batch upload via a single --files-from copy. A --files-from
        # copy keeps each file's source path, so renamed files go one at a time.
        if cryption_type == config.CryptionType.NONE:
            same_name = []
            renamed = []
            for action in actions:
                src_rel = action.get("src", "")
                if action.get("dest", src_rel) == src_rel:
                    same_name.append(action)
                else:
                    renamed.append(action)
            succeeded, failed = super().sync_batch_from(
                src_backend = src_backend,
                actions = renamed,
                cryption_type = cryption_type,
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
            files_from_ok, files_from = fileops.create_temporary_file(suffix = ".txt")
            if not files_from_ok:
                logger.log_error("Failed to create temporary file")
                return (succeeded, failed + src_rels)
            try:
                ok = serialization.write_text_file(files_from, "\n".join(src_rels))
                if not ok:
                    logger.log_error("Failed to write file list %s" % files_from)
                else:
                    ok = sync.upload_files_to_remote(
                        remote_name = self.remote_name,
                        remote_type = self.remote_type,
                        remote_path = self.remote_path,
                        local_path = src_root,
                        files_from = files_from,
                        update_sidecar = False,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
            finally:
                fileops.remove_file(files_from, exit_on_failure = False)
            if ok:
                return (succeeded + src_rels, failed)
            return (succeeded, failed + src_rels)

        # Encrypted batch upload. Encrypt into a staging tree and upload, but in
        # size-bounded batches so temp space never holds the whole delta at once, and
        # stage on the cache volume (room to spare) rather than /tmp (often small/tmpfs).
        if cryption_type == config.CryptionType.ENCRYPT:
            logger.log_info("Encrypting and uploading %d files to %s (batched)..." % (len(actions), self.remote_name))
            if pretend_run:
                for action in actions:
                    logger.log_info("Would encrypt and upload: %s" % action.get("dest", action.get("src", "")))
                return ([a.get("dest", a.get("src", "")) for a in actions], [])
            stage_parent = environment.get_cache_root_dir()
            max_batch_bytes = 4 * 1024 * 1024 * 1024  # ~4 GiB of staged files per upload

            # Group actions into size-bounded batches by source file size; a source that
            # is gone fails on its own rather than stopping the whole transfer
            succeeded = []
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

            # Process each batch: stage -> encrypt -> single upload -> clear staging
            for batch in batches:
                staging_ok, staging = fileops.create_temporary_directory(directory = stage_parent, verbose = verbose)
                if not staging_ok:
                    logger.log_error("Failed to create staging directory for encrypted upload")
                    failed.extend([a.get("dest", a.get("src", "")) for a in batch])
                    continue
                staged = []
                try:
                    for action in batch:
                        src_rel = action.get("src", "")
                        dest_rel = action.get("dest", src_rel)
                        src_full = paths.join_paths(src_root, src_rel)
                        dest_dir_rel = paths.get_filename_directory(dest_rel)
                        enc_name = cryption.generate_encrypted_filename(paths.get_filename_file(dest_rel))
                        staged_dir = paths.join_paths(staging, dest_dir_rel) if dest_dir_rel else staging
                        fileops.make_directory(src = staged_dir)
                        if cryption.encrypt_file(
                            src = src_full,
                            passphrase = passphrase,
                            output_file = paths.join_paths(staged_dir, enc_name),
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure):
                            staged.append(dest_rel)
                        else:
                            logger.log_error("Failed to encrypt: %s" % dest_rel)
                            failed.append(dest_rel)

                    # Single upload of this batch's staging tree (mirrors dest structure)
                    if staged:
                        if sync.upload_files_to_remote(
                            remote_name = self.remote_name,
                            remote_type = self.remote_type,
                            remote_path = self.remote_path,
                            local_path = staging,
                            update_sidecar = False,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure):
                            succeeded.extend(staged)
                        else:
                            failed.extend(staged)
                finally:
                    fileops.remove_directory(staging, exit_on_failure = False)
            return (succeeded, failed)

        # Other cryption types (e.g. decrypt): per-file fallback
        return super().sync_batch_from(
            src_backend = src_backend,
            actions = actions,
            cryption_type = cryption_type,
            passphrase = passphrase,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    def update_sidecar_from_local(
        self,
        local_root_path,
        excludes = [],
        clear_first = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Optionally clear the existing sidecar first (one-time purge of stale entries).
        # Rebuilding on top of a sidecar that could not be cleared would keep the stale ones.
        if clear_first:
            db_path = sync.get_hash_database_path(self.remote_path)
            if sync.does_file_exist(self.remote_name, self.remote_type, db_path, verbose = verbose):
                if not sync.clear_hash_sidecar_files(
                    remote_name = self.remote_name,
                    remote_type = self.remote_type,
                    remote_path = self.remote_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure):
                    logger.log_error("Failed to clear the hash sidecar on %s" % self.remote_name)
                    return False

        # Rebuild the sidecar from authoritative local (plaintext) content
        return sync.upload_hash_sidecar_files(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = self.remote_path,
            local_path = local_root_path,
            local_root = self.remote_path,
            excludes = excludes,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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

    def sync_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        cryption_type = None,
        passphrase = None,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Default cryption type
        if cryption_type is None:
            cryption_type = config.CryptionType.NONE
        if cryption_type not in CRYPTION_TYPES:
            logger.log_error("Unknown cryption type: %s" % cryption_type)
            return False
        if not isinstance(src_backend, (LocalBackend, RemoteBackend)):
            logger.log_error("Unsupported source locker: %s" % type(src_backend).__name__)
            return False

        # Plain remote to remote copy never lands locally
        dest_remote_path = paths.join_paths(self.remote_path, dest_rel_path)
        if isinstance(src_backend, RemoteBackend) and cryption_type == config.CryptionType.NONE:
            return sync.copy_remote_to_remote(
                src_remote_name = src_backend.remote_name,
                src_remote_type = src_backend.remote_type,
                src_remote_path = paths.join_paths(src_backend.remote_path, src_rel_path),
                dest_remote_name = self.remote_name,
                dest_remote_type = self.remote_type,
                dest_remote_path = dest_remote_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Plain local upload
        if isinstance(src_backend, LocalBackend):
            src_full_path = paths.join_paths(src_backend.get_root_path(), src_rel_path)
            if cryption_type == config.CryptionType.NONE:
                return self.upload_local_path(
                    src_full_path = src_full_path,
                    dest_rel_path = dest_rel_path,
                    local_root = self.remote_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

        # Conversions are staged under the destination name, encrypted when encrypting
        dest_name = paths.get_filename_file(dest_rel_path)
        if cryption_type == config.CryptionType.ENCRYPT:
            dest_name = cryption.generate_encrypted_filename(dest_name)
        temp_dir_ok, temp_dir = fileops.create_temporary_directory(verbose = verbose)
        if not temp_dir_ok:
            logger.log_error("Failed to create temp directory for sync to %s" % self.remote_name)
            return False
        try:
            staged_dir = paths.join_paths(temp_dir, "staged")
            staged_file = paths.join_paths(staged_dir, dest_name)
            fileops.make_directory(src = staged_dir, verbose = verbose, pretend_run = pretend_run)

            # Get a local copy of the source
            if isinstance(src_backend, LocalBackend):
                source_file = src_full_path
            else:
                stored_rel_path = src_rel_path
                if cryption_type == config.CryptionType.DECRYPT:
                    stored_rel_path = src_backend.get_stored_rel_path(src_rel_path)
                download_dir = paths.join_paths(temp_dir, "download")
                source_file = paths.join_paths(download_dir, paths.get_filename_file(stored_rel_path))
                if not sync.download_files_from_remote(
                    remote_name = src_backend.remote_name,
                    remote_type = src_backend.remote_type,
                    remote_path = paths.join_paths(src_backend.remote_path, stored_rel_path),
                    local_path = download_dir + os.sep,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure):
                    return False

            # Stage it under the destination name, converting it on the way
            if not get_cryption_function(cryption_type)(
                src = source_file,
                passphrase = passphrase,
                output_file = staged_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False

            # Upload the staged file
            return sync.upload_files_to_remote(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = paths.get_filename_directory(dest_remote_path),
                local_path = staged_file,
                local_root = self.remote_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        finally:
            fileops.remove_directory(temp_dir, exit_on_failure = False)

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
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    def file_exists(self, rel_path):
        full_path = paths.join_paths(self.remote_path, rel_path)
        return sync.does_path_exist(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = full_path)

    def path_exists(self, rel_path):
        full_path = paths.join_paths(self.remote_path, rel_path)
        return sync.does_path_exist(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = full_path)

    def path_contains_files(self, rel_path):
        full_path = paths.join_paths(self.remote_path, rel_path)
        return sync.does_path_contain_files(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = full_path)

###########################################################
# Factory Function
###########################################################

def get_backend_for_locker(locker_info):
    if locker_info.is_local_only():
        return LocalBackend(locker_info)
    else:
        remote_name = locker_info.get_name()
        remote_type = locker_info.get_type()
        if remote_name and remote_type and sync.is_remote_configured(remote_name, remote_type):
            return RemoteBackend(locker_info)
        else:
            return LocalBackend(locker_info)
