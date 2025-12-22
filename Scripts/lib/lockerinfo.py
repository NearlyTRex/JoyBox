# Imports
import os
import os.path
import sys

# Local imports
import config
import system
import environment
import ini

# Locker info
class LockerInfo:
    def __init__(self, locker_type = None):
        if not locker_type:
            locker_type = config.LockerType.HETZNER
        self.locker_type = locker_type
        self.remote_type = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_type")
        self.remote_name = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_name")
        self.remote_path = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_path")
        self.remote_config = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_config")
        self.remote_token = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_token")
        self.remote_mount_path = ini.get_ini_path_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_mount_path")
        self.remote_mount_flags = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_remote_mount_flags").split(",")
        self.local_path = ini.get_ini_path_value("UserData.Share", f"locker_{self.locker_type.lower()}_local_path")
        self.passphrase = ini.get_ini_value("UserData.Share", f"locker_{self.locker_type.lower()}_passphrase")

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
