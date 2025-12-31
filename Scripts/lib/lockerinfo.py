# Imports
import os
import os.path
import sys

# Local imports
import config
import ini

# Locker info
class LockerInfo:
    def __init__(self, locker_type = None):
        if not locker_type:
            locker_type = config.LockerType.HETZNER
        self.locker_type = locker_type
        if self.locker_type == config.LockerType.EXTERNAL:
            self.remote_type = None
            self.remote_name = None
            self.remote_path = None
            self.remote_config = None
            self.remote_token = None
            self.remote_mount_path = None
            self.remote_mount_flags = []
        else:
            self.remote_type = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_type")
            self.remote_name = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_name")
            self.remote_path = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_path")
            self.remote_config = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_config")
            self.remote_token = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_token")
            self.remote_mount_path = ini.get_ini_path_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_mount_path")
            self.remote_mount_flags = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_mount_flags").split(",")
        self.local_path = ini.get_ini_path_value("UserData.Share", f"locker_{self.locker_type.lower()}_local_path")
        self.passphrase = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_passphrase")

        # Parse excluded sync paths into list
        excluded_str = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_excluded_sync_paths")
        self.excluded_sync_paths = [p.strip() for p in excluded_str.split(",") if p.strip()] if excluded_str else []

        # Parse decrypt on sync into bool
        decrypt_str = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_decrypt_on_sync")
        self.decrypt_on_sync = decrypt_str.lower() == "true" if decrypt_str else False

    def get_remote_type(self):
        return self.remote_type

    def get_remote_name(self):
        return self.remote_name

    def get_remote_path(self):
        return self.remote_path

    def get_remote_config(self):
        return self.remote_config

    def get_remote_token(self):
        return self.remote_token

    def get_remote_mount_path(self):
        return self.remote_mount_path

    def get_remote_mount_flags(self):
        return self.remote_mount_flags

    def get_local_path(self):
        return self.local_path

    def get_passphrase(self):
        return self.passphrase

    def get_excluded_sync_paths(self):
        return self.excluded_sync_paths

    def get_decrypt_on_sync(self):
        return self.decrypt_on_sync

    def is_local_only(self):
        return self.remote_type is None

    def get_backend_type(self):
        if self.locker_type == config.LockerType.EXTERNAL:
            return "external"
        elif self.remote_type is None:
            return "local"
        else:
            return "remote"

    def get_locker_root_path(self):
        if self.is_local_only():
            return self.local_path
        else:
            if self.remote_mount_path:
                return self.remote_mount_path
            return self.remote_path

    def get_locker_name(self):
        return self.locker_type.val() if hasattr(self.locker_type, 'val') else str(self.locker_type)
