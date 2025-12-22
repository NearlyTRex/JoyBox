# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import release
import programs
import toolbase

# Config files
config_files = {}

# ProjectCTR tool
class ProjectCTR(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "ProjectCTR"

    # Get config
    def GetConfig(self):
        return {

            # CtrMakeRom
            "CtrMakeRom": {
                "program": {
                    "windows": "CtrMakeRom/windows/makerom.exe",
                    "linux": "CtrMakeRom/linux/makerom"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            },

            # CtrTool
            "CtrTool": {
                "program": {
                    "windows": "CtrTool/windows/ctrtool.exe",
                    "linux": "CtrTool/linux/ctrtool"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("CtrMakeRom", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "makerom",
                ends_with = "win_x86_64.zip",
                search_file = "makerom.exe",
                install_name = "CtrMakeRom",
                install_dir = programs.GetProgramInstallDir("CtrMakeRom", "windows"),
                backups_dir = programs.GetProgramBackupDir("CtrMakeRom", "windows"),
                install_files = ["makerom.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrMakeRom")
                return False

        # Download windows program
        if programs.ShouldProgramBeInstalled("CtrTool", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "ctrtool",
                ends_with = "win_x64.zip",
                search_file = "ctrtool.exe",
                install_name = "CtrTool",
                install_dir = programs.GetProgramInstallDir("CtrTool", "windows"),
                backups_dir = programs.GetProgramBackupDir("CtrTool", "windows"),
                install_files = ["ctrtool.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrTool")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("CtrMakeRom", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "makerom",
                ends_with = "ubuntu_x86_64.zip",
                search_file = "makerom",
                install_name = "CtrMakeRom",
                install_dir = programs.GetProgramInstallDir("CtrMakeRom", "linux"),
                backups_dir = programs.GetProgramBackupDir("CtrMakeRom", "linux"),
                install_files = ["makerom"],
                release_type = config.ReleaseType.ARCHIVE,
                chmod_files = [
                    {
                        "file": "makerom",
                        "perms": 755
                    }
                ],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrMakeRom")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("CtrTool", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "ctrtool",
                ends_with = "ubuntu_x86_64.zip",
                search_file = "ctrtool",
                install_name = "CtrTool",
                install_dir = programs.GetProgramInstallDir("CtrTool", "linux"),
                backups_dir = programs.GetProgramBackupDir("CtrTool", "linux"),
                install_files = ["ctrtool"],
                release_type = config.ReleaseType.ARCHIVE,
                chmod_files = [
                    {
                        "file": "ctrtool",
                        "perms": 755
                    }
                ],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrTool")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("CtrMakeRom", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("CtrMakeRom", "windows"),
                install_name = "CtrMakeRom",
                install_dir = programs.GetProgramInstallDir("CtrMakeRom", "windows"),
                search_file = "makerom.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrMakeRom")
                return False

        # Setup windows program
        if programs.ShouldProgramBeInstalled("CtrTool", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("CtrTool", "windows"),
                install_name = "CtrTool",
                install_dir = programs.GetProgramInstallDir("CtrTool", "windows"),
                search_file = "ctrtool.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrTool")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("CtrMakeRom", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("CtrMakeRom", "linux"),
                install_name = "CtrMakeRom",
                install_dir = programs.GetProgramInstallDir("CtrMakeRom", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrMakeRom")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("CtrTool", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("CtrTool", "linux"),
                install_name = "CtrTool",
                install_dir = programs.GetProgramInstallDir("CtrTool", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CtrTool")
                return False
        return True
