# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import environment
import release
import programs
import toolbase
import ini

# Config files
config_files = {}
config_file_general = """
[GDRIVE_NAME]
type = GDRIVE_TYPE
client_id =
client_secret =
scope = drive
token = GDRIVE_TOKEN
team_drive =
root_folder_id =

[HETZNER_NAME]
type = HETZNER_TYPE
host = HETZNER_HOST
user = HETZNER_USER
pass = HETZNER_PASS
shell_type = unix
md5sum_command = none
sha1sum_command = none
"""
config_files["RClone/windows/rclone.conf"] = config_file_general
config_files["RClone/linux/rclone.conf"] = config_file_general

# RClone tool
class RClone(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "RClone"

    # Get config
    def GetConfig(self):
        return {
            "RClone": {
                "program": {
                    "windows": "RClone/windows/rclone.exe",
                    "linux": "RClone/linux/rclone"
                },
                "config_file": {
                    "windows": "RClone/windows/rclone.conf",
                    "linux": "RClone/linux/rclone.conf"
                },
                "cache_dir": {
                    "windows": "RClone/windows/cache",
                    "linux": "RClone/linux/cache"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("RClone", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://downloads.rclone.org/rclone-current-windows-amd64.zip",
                search_file = "rclone.exe",
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "windows"),
                backups_dir = programs.GetProgramBackupDir("RClone", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RClone")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("RClone", "linux"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://downloads.rclone.org/rclone-current-linux-amd64.zip",
                search_file = "rclone",
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "linux"),
                backups_dir = programs.GetProgramBackupDir("RClone", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RClone")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("RClone", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RClone", "windows"),
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "windows"),
                search_file = "rclone.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RClone")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("RClone", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RClone", "linux"),
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RClone")
                return False
        return True

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Get gdrive options
        gdrive_remote_name = ini.GetIniValue("UserData.Share", "locker_gdrive_remote_name", throw_exception = False)
        gdrive_remote_type = ini.GetIniValue("UserData.Share", "locker_gdrive_remote_type", throw_exception = False)
        gdrive_remote_token = ini.GetIniValue("UserData.Share", "locker_gdrive_remote_token", throw_exception = False)

        # Get hetzner options
        hetzner_remote_name = ini.GetIniValue("UserData.Share", "locker_hetzner_remote_name", throw_exception = False)
        hetzner_remote_type = ini.GetIniValue("UserData.Share", "locker_hetzner_remote_type", throw_exception = False)
        hetzner_remote_config = json.loads(ini.GetIniValue("UserData.Share", "locker_hetzner_remote_config", throw_exception = False))
        if not hetzner_remote_config:
            hetzner_remote_config = {}
        hetzner_remote_host = hetzner_remote_config.get("host")
        hetzner_remote_user = hetzner_remote_config.get("user")
        hetzner_remote_pass = hetzner_remote_config.get("pass")

        # Create config files
        for config_filename, config_contents in config_files.items():
            config_contents = config_contents.strip()

            # Replace gdrive tokens
            if gdrive_remote_name:
                config_contents = config_contents.replace(config.token_gdrive_name, gdrive_remote_name)
            if gdrive_remote_type:
                config_contents = config_contents.replace(config.token_gdrive_type, gdrive_remote_type)
            if gdrive_remote_token:
                config_contents = config_contents.replace(config.token_gdrive_token, gdrive_remote_token)

            # Replace hetzner tokens
            if hetzner_remote_name:
                config_contents = config_contents.replace(config.token_hetzner_name, hetzner_remote_name)
            if hetzner_remote_type:
                config_contents = config_contents.replace(config.token_hetzner_type, hetzner_remote_type)
            if hetzner_remote_host:
                config_contents = config_contents.replace(config.token_hetzner_host, hetzner_remote_host)
            if hetzner_remote_user:
                config_contents = config_contents.replace(config.token_hetzner_user, hetzner_remote_user)
            if hetzner_remote_pass:
                config_contents = config_contents.replace(config.token_hetzner_pass, hetzner_remote_pass)

            # Write config file
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetToolsRootDir(), config_filename),
                contents = config_contents,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup RClone config files")
                return False
        return True
