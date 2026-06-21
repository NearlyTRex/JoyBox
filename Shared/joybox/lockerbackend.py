# Imports
import os
import os.path
import fnmatch
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
        pass

    @abstractmethod
    def list_files_with_hashes(
        self,
        excludes = [],
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """
        List all files with their hashes.
        Returns dict keyed by relative path: {filename, dir, hash, size, mtime}
        """
        pass

    @abstractmethod
    def recycle_file(
        self,
        rel_path,
        recycle_folder = ".recycle_bin",
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """Move file to recycle bin instead of deleting"""
        pass

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
        pass

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
        pass

    @abstractmethod
    def file_exists(self, rel_path):
        """Check if file exists at relative path"""
        pass

    @abstractmethod
    def path_exists(self, rel_path):
        """Check if path (file or directory) exists at relative path"""
        pass

    @abstractmethod
    def path_contains_files(self, rel_path):
        """Check if path contains any files"""
        pass

    def get_relative_path(self, full_path):
        """Convert a full path to a relative path within this locker"""
        root = self.get_root_path()
        if root and full_path.startswith(root):
            rel = full_path[len(root):]
            if rel.startswith(os.sep):
                rel = rel[1:]
            return rel
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
        if not paths.does_path_exist(self.root_path):
            logger.log_warning("Local path does not exist: %s" % self.root_path)
            return hash_map

        # Build the list of actual files to hash (apply excludes, skip non-files)
        targets = []
        for rel_path in paths.build_file_list(self.root_path, use_relative_paths = True):
            if self._matches_exclude(rel_path, excludes):
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

        # Get destination path
        dest_full_path = paths.join_paths(self.root_path, dest_rel_path)

        # Handle remote source
        if isinstance(src_backend, RemoteBackend):
            src_remote_path = paths.join_paths(src_backend.remote_path, src_rel_path)

            # If no cryption needed, download directly
            if cryption_type == config.CryptionType.NONE:
                return sync.download_files_from_remote(
                    remote_name = src_backend.remote_name,
                    remote_type = src_backend.remote_type,
                    remote_path = src_remote_path,
                    local_path = paths.get_filename_directory(dest_full_path),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

            # Download to temp, then encrypt/decrypt
            temp_dir_ok, temp_dir = fileops.create_temporary_directory(verbose = verbose)
            if not temp_dir_ok:
                logger.log_error("Failed to create temp directory for sync")
                return False
            temp_file = paths.join_paths(temp_dir, paths.get_filename_file(src_rel_path))
            try:
                # Download to temp
                success = sync.download_files_from_remote(
                    remote_name = src_backend.remote_name,
                    remote_type = src_backend.remote_type,
                    remote_path = src_remote_path,
                    local_path = temp_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False

                # Encrypt or decrypt
                if cryption_type == config.CryptionType.DECRYPT:
                    return cryption.decrypt_file(
                        src = temp_file,
                        passphrase = passphrase,
                        output_file = dest_full_path,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                elif cryption_type == config.CryptionType.ENCRYPT:
                    return cryption.encrypt_file(
                        src = temp_file,
                        passphrase = passphrase,
                        output_file = dest_full_path,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
            finally:
                fileops.remove_directory(temp_dir)
            return False

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
        if cryption_type == config.CryptionType.DECRYPT:
            return cryption.decrypt_file(
                src = src_full_path,
                passphrase = passphrase,
                output_file = dest_full_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        elif cryption_type == config.CryptionType.ENCRYPT:
            return cryption.encrypt_file(
                src = src_full_path,
                passphrase = passphrase,
                output_file = dest_full_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        return False

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

    def _matches_exclude(self, rel_path, excludes):
        for pattern in excludes:
            if fnmatch.fnmatch(rel_path, pattern):
                return True
            parts = rel_path.split(os.sep)
            for i in range(len(parts)):
                partial = os.sep.join(parts[:i+1])
                if fnmatch.fnmatch(partial, pattern.rstrip("/**")):
                    return True
        return False

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

        # Plain (unencrypted) batch upload via a single --files-from copy
        if cryption_type == config.CryptionType.NONE:
            src_rels = [a.get("src", "") for a in actions]
            dest_rels = [a.get("dest", a.get("src", "")) for a in actions]
            logger.log_info("Uploading %d files to %s (batched)..." % (len(src_rels), self.remote_name))
            if pretend_run:
                for rel in src_rels:
                    logger.log_info("Would upload: %s" % rel)
                return (dest_rels, [])
            files_from = fileops.create_temporary_file(suffix = ".txt")
            try:
                serialization.write_text_file(files_from, "\n".join(src_rels))
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
                fileops.remove_file(files_from)
            return (dest_rels, []) if ok else ([], dest_rels)

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

            # Group actions into size-bounded batches by source file size
            batches = []
            current = []
            current_bytes = 0
            for action in actions:
                size = paths.get_file_size(paths.join_paths(src_root, action.get("src", "")))
                if current and current_bytes + size > max_batch_bytes:
                    batches.append(current)
                    current = []
                    current_bytes = 0
                current.append(action)
                current_bytes += size
            if current:
                batches.append(current)

            # Process each batch: stage -> encrypt -> single upload -> clear staging
            succeeded = []
            failed = []
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
                    fileops.remove_directory(staging)
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

        # Optionally clear the existing sidecar first (one-time purge of stale entries)
        if clear_first:
            sync.clear_hash_sidecar_files(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = self.remote_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

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

        # On encrypted lockers the file is stored under its encrypted name, so target
        # that on the remote rather than the plaintext relative path.
        target_rel = rel_path
        if self.locker_info.is_encrypted():
            dir_rel = paths.get_filename_directory(rel_path)
            enc_name = cryption.generate_encrypted_filename(paths.get_filename_file(rel_path))
            target_rel = (paths.join_paths(dir_rel, enc_name) if dir_rel else enc_name).replace("\\", "/")

        # Create a temporary file list for the recycle operation
        temp_file = fileops.create_temporary_file(suffix = ".txt")
        serialization.write_text_file(temp_file, target_rel)

        # Recycle files
        result = sync.recycle_files_on_remote(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            remote_path = self.remote_path,
            files_from = temp_file,
            recycle_folder = recycle_folder,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Clean up temp file
        fileops.remove_file(temp_file)
        return result

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

        # Handle local source
        dest_remote_path = paths.join_paths(self.remote_path, dest_rel_path)
        if isinstance(src_backend, LocalBackend):
            src_full_path = paths.join_paths(src_backend.get_root_path(), src_rel_path)

            # If no cryption needed, upload directly
            if cryption_type == config.CryptionType.NONE:
                if paths.is_path_directory(src_full_path):
                    upload_remote_path = dest_remote_path
                else:
                    upload_remote_path = paths.get_filename_directory(dest_remote_path)
                return sync.upload_files_to_remote(
                    remote_name = self.remote_name,
                    remote_type = self.remote_type,
                    remote_path = upload_remote_path,
                    local_path = src_full_path,
                    local_root = self.remote_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

            # Encrypt/decrypt to temp, then upload
            temp_dir_ok, temp_dir = fileops.create_temporary_directory(verbose = verbose)
            if not temp_dir_ok:
                logger.log_error("Failed to create temp directory for encrypted upload")
                return False
            try:
                if cryption_type == config.CryptionType.ENCRYPT:
                    temp_file = paths.join_paths(temp_dir, cryption.generate_encrypted_filename(paths.get_filename_file(dest_rel_path)))
                    success = cryption.encrypt_file(
                        src = src_full_path,
                        passphrase = passphrase,
                        output_file = temp_file,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                elif cryption_type == config.CryptionType.DECRYPT:
                    temp_file = paths.join_paths(temp_dir, paths.get_filename_file(src_rel_path))
                    success = cryption.decrypt_file(
                        src = src_full_path,
                        passphrase = passphrase,
                        output_file = temp_file,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                else:
                    return False
                if not success:
                    return False

                # Upload the processed file
                return sync.upload_files_to_remote(
                    remote_name = self.remote_name,
                    remote_type = self.remote_type,
                    remote_path = paths.get_filename_directory(dest_remote_path),
                    local_path = temp_file,
                    local_root = self.remote_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            finally:
                fileops.remove_directory(temp_dir)

        # Handle remote source (remote to remote copy)
        if isinstance(src_backend, RemoteBackend):
            src_remote_path = paths.join_paths(src_backend.remote_path, src_rel_path)

            # If no cryption needed, copy directly
            if cryption_type == config.CryptionType.NONE:
                return sync.copy_remote_to_remote(
                    src_remote_name = src_backend.remote_name,
                    src_remote_type = src_backend.remote_type,
                    src_remote_path = src_remote_path,
                    dest_remote_name = self.remote_name,
                    dest_remote_type = self.remote_type,
                    dest_remote_path = dest_remote_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

            # Download, encrypt/decrypt, then upload
            temp_dir_ok, temp_dir = fileops.create_temporary_directory(verbose = verbose)
            if not temp_dir_ok:
                logger.log_error("Failed to create temp directory for remote-to-remote sync")
                return False
            try:
                temp_download = paths.join_paths(temp_dir, paths.get_filename_file(src_rel_path))

                # Download from source remote
                success = sync.download_files_from_remote(
                    remote_name = src_backend.remote_name,
                    remote_type = src_backend.remote_type,
                    remote_path = src_remote_path,
                    local_path = temp_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False

                # Encrypt or decrypt
                if cryption_type == config.CryptionType.ENCRYPT:
                    temp_processed = paths.join_paths(temp_dir, cryption.generate_encrypted_filename(temp_download))
                    success = cryption.encrypt_file(
                        src = temp_download,
                        passphrase = passphrase,
                        output_file = temp_processed,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                elif cryption_type == config.CryptionType.DECRYPT:
                    temp_processed = paths.join_paths(temp_dir, "decrypted_" + paths.get_filename_file(src_rel_path))
                    success = cryption.decrypt_file(
                        src = temp_download,
                        passphrase = passphrase,
                        output_file = temp_processed,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                else:
                    return False
                if not success:
                    return False

                # Upload to destination remote
                return sync.upload_files_to_remote(
                    remote_name = self.remote_name,
                    remote_type = self.remote_type,
                    remote_path = paths.get_filename_directory(dest_remote_path),
                    local_path = temp_processed,
                    local_root = self.remote_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            finally:
                fileops.remove_directory(temp_dir)
        return False

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
        dest_remote_path = paths.join_paths(self.remote_path, dest_rel_path)
        return sync.upload_files_to_remote(
            remote_name = self.remote_name,
            remote_type = self.remote_type,
            local_path = src_abs_path,
            remote_path = paths.get_filename_directory(dest_remote_path),
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
