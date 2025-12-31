# Imports
import os
import os.path
import fnmatch
from abc import ABC, abstractmethod

# Local imports
import config
import logger
import paths
import fileops
import hashing
import sync
import serialization

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
    def copy_file_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        """Copy a file from another backend to this one"""
        pass

    @abstractmethod
    def file_exists(self, rel_path):
        """Check if file exists at relative path"""
        pass

###########################################################
# Local Backend (Local folders and external mounted drives)
###########################################################

class LocalBackend(LockerBackend):
    def __init__(self, locker_info):
        super().__init__(locker_info)
        self.root_path = locker_info.get_local_path() or locker_info.get_remote_mount_path()

    def get_root_path(self):
        return self.root_path

    def list_files_with_hashes(
        self,
        excludes = [],
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check root path
        hash_map = {}
        if not paths.does_path_exist(self.root_path):
            logger.log_warning("Local path does not exist: %s" % self.root_path)
            return hash_map

        # Build file list
        file_list = paths.build_file_list(self.root_path, use_relative_paths = True)
        total_files = len(file_list)

        # Build hash map
        if verbose:
            logger.log_info("Building hash map for local path: %s" % self.root_path)
        for idx, rel_path in enumerate(file_list):

            # Check exclusions
            if self._matches_exclude(rel_path, excludes):
                continue

            # Skip if not a file
            full_path = paths.join_paths(self.root_path, rel_path)
            if not paths.is_path_file(full_path):
                continue

            # Get file info
            file_size = paths.get_file_size(full_path)
            file_mtime = paths.get_file_mod_time(full_path)
            file_name = paths.get_filename_file(rel_path)
            file_dir = paths.get_filename_directory(rel_path)

            # Calculate MD5 hash
            file_hash = hashing.calculate_file_md5(
                src = full_path,
                verbose = False,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

            # Add to map
            hash_map[rel_path] = {
                "filename": file_name,
                "dir": file_dir,
                "hash": file_hash,
                "size": file_size,
                "mtime": file_mtime
            }

            # Log progress
            if verbose and (idx + 1) % 100 == 0:
                logger.log_info("Processed %d/%d files" % (idx + 1, total_files))
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

    def copy_file_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get paths
        src_full_path = paths.join_paths(src_backend.get_root_path(), src_rel_path)
        dest_full_path = paths.join_paths(self.root_path, dest_rel_path)

        # Handle remote source
        if isinstance(src_backend, RemoteBackend):
            return sync.download_files_from_remote(
                remote_name = src_backend.remote_name,
                remote_type = src_backend.remote_type,
                remote_path = paths.join_paths(src_backend.remote_path, src_rel_path),
                local_path = paths.get_filename_directory(dest_full_path),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Handle local source
        return fileops.smart_copy(
            src = src_full_path,
            dest = dest_full_path,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    def file_exists(self, rel_path):
        return paths.is_path_file(paths.join_paths(self.root_path, rel_path))

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
        self.remote_name = locker_info.get_remote_name()
        self.remote_type = locker_info.get_remote_type()
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

    def recycle_file(
        self,
        rel_path,
        recycle_folder = ".recycle_bin",
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Create a temporary file list for the recycle operation
        temp_file = fileops.create_temporary_file(suffix = ".txt")
        serialization.write_text_file(temp_file, rel_path)

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

    def copy_file_from(
        self,
        src_backend,
        src_rel_path,
        dest_rel_path,
        show_progress = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Handle local source
        if isinstance(src_backend, LocalBackend):
            src_full_path = paths.join_paths(src_backend.get_root_path(), src_rel_path)
            dest_remote_path = paths.join_paths(self.remote_path, paths.get_filename_directory(dest_rel_path))
            return sync.upload_files_to_remote(
                remote_name = self.remote_name,
                remote_type = self.remote_type,
                remote_path = dest_remote_path,
                local_path = src_full_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Handle remote source (remote to remote copy)
        if isinstance(src_backend, RemoteBackend):
            return sync.copy_remote_to_remote(
                src_remote_name = src_backend.remote_name,
                src_remote_type = src_backend.remote_type,
                src_remote_path = paths.join_paths(src_backend.remote_path, src_rel_path),
                dest_remote_name = self.remote_name,
                dest_remote_type = self.remote_type,
                dest_remote_path = paths.join_paths(self.remote_path, dest_rel_path),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        return False

    def file_exists(self, rel_path):
        full_path = paths.join_paths(self.remote_path, rel_path)
        return sync.does_path_exist(
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
        remote_name = locker_info.get_remote_name()
        remote_type = locker_info.get_remote_type()
        if remote_name and remote_type and sync.is_remote_configured(remote_name, remote_type):
            return RemoteBackend(locker_info)
        else:
            return LocalBackend(locker_info)
