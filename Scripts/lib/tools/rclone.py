# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import logger
import paths
import environment
import fileops
import release
import programs
import toolbase
import ini

# Config file templates
config_template_gdrive = """
[GDRIVE_NAME]
type = GDRIVE_TYPE
client_id =
client_secret =
scope = drive
token = GDRIVE_TOKEN
team_drive =
root_folder_id =
"""
config_template_hetzner = """
[HETZNER_NAME]
type = HETZNER_TYPE
host = HETZNER_HOST
user = HETZNER_USER
pass = HETZNER_PASS
shell_type = unix
md5sum_command = none
sha1sum_command = none
"""

# RClone tool
class RClone(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "RClone"

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("RClone", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://downloads.rclone.org/rclone-current-windows-amd64.zip",
                search_file = "rclone.exe",
                install_name = "RClone",
                install_dir = programs.get_program_install_dir("RClone", "windows"),
                backups_dir = programs.get_program_backup_dir("RClone", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone")
                return False

        # Download linux program
        if programs.should_program_be_installed("RClone", "linux"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://downloads.rclone.org/rclone-current-linux-amd64.zip",
                search_file = "rclone",
                install_name = "RClone",
                install_dir = programs.get_program_install_dir("RClone", "linux"),
                backups_dir = programs.get_program_backup_dir("RClone", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("RClone", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("RClone", "windows"),
                install_name = "RClone",
                install_dir = programs.get_program_install_dir("RClone", "windows"),
                search_file = "rclone.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone")
                return False

        # Setup linux program
        if programs.should_program_be_installed("RClone", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("RClone", "linux"),
                install_name = "RClone",
                install_dir = programs.get_program_install_dir("RClone", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Get gdrive options
        gdrive_remote_name = ini.GetIniValue("UserData.Share", "locker_gdrive_remote_name", throw_exception = False)
        gdrive_remote_type = ini.GetIniValue("UserData.Share", "locker_gdrive_remote_type", throw_exception = False)
        gdrive_remote_token = ini.GetIniValue("UserData.Share", "locker_gdrive_remote_token", throw_exception = False)

        # Get hetzner options
        hetzner_remote_name = ini.GetIniValue("UserData.Share", "locker_hetzner_remote_name", throw_exception = False)
        hetzner_remote_type = ini.GetIniValue("UserData.Share", "locker_hetzner_remote_type", throw_exception = False)
        hetzner_remote_config_str = ini.GetIniValue("UserData.Share", "locker_hetzner_remote_config", throw_exception = False)
        hetzner_remote_config = {}
        if hetzner_remote_config_str:
            try:
                hetzner_remote_config = json.loads(hetzner_remote_config_str)
            except:
                pass
        hetzner_remote_host = hetzner_remote_config.get("host")
        hetzner_remote_user = hetzner_remote_config.get("user")
        hetzner_remote_pass = hetzner_remote_config.get("pass")

        # Build config contents - only include sections with valid credentials
        config_contents = ""

        # Add gdrive section only if we have the required credentials
        if gdrive_remote_name and gdrive_remote_type and gdrive_remote_token:
            gdrive_section = config_template_gdrive.strip()
            gdrive_section = gdrive_section.replace(config.token_gdrive_name, gdrive_remote_name)
            gdrive_section = gdrive_section.replace(config.token_gdrive_type, gdrive_remote_type)
            gdrive_section = gdrive_section.replace(config.token_gdrive_token, gdrive_remote_token)
            config_contents += gdrive_section + "\n\n"

        # Add hetzner section only if we have the required credentials
        if hetzner_remote_name and hetzner_remote_type and hetzner_remote_host and hetzner_remote_user and hetzner_remote_pass:
            hetzner_section = config_template_hetzner.strip()
            hetzner_section = hetzner_section.replace(config.token_hetzner_name, hetzner_remote_name)
            hetzner_section = hetzner_section.replace(config.token_hetzner_type, hetzner_remote_type)
            hetzner_section = hetzner_section.replace(config.token_hetzner_host, hetzner_remote_host)
            hetzner_section = hetzner_section.replace(config.token_hetzner_user, hetzner_remote_user)
            hetzner_section = hetzner_section.replace(config.token_hetzner_pass, hetzner_remote_pass)
            config_contents += hetzner_section + "\n"

        # Write config files for each platform
        config_files = [
            "RClone/windows/rclone.conf",
            "RClone/linux/rclone.conf"
        ]
        for config_filename in config_files:
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RClone config files")
                return False
        return True
