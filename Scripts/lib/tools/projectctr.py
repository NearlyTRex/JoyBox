# Imports
import os, os.path
import sys

# Local imports
import config
import system
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
    def Setup(self, verbose = False, exit_on_failure = False):

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
                install_files = ["makerom.exe"],
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup CtrMakeRom")
        if programs.ShouldProgramBeInstalled("CtrTool", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "ctrtool",
                ends_with = "win_x64.zip",
                search_file = "ctrtool.exe",
                install_name = "CtrTool",
                install_dir = programs.GetProgramInstallDir("CtrTool", "windows"),
                install_files = ["ctrtool.exe"],
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup CtrTool")

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
                install_files = ["makerom"],
                release_type = config.release_type_archive,
                chmod_files = [
                    {
                        "file": "makerom",
                        "perms": 755
                    }
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup CtrMakeRom")
        if programs.ShouldProgramBeInstalled("CtrTool", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "ctrtool",
                ends_with = "ubuntu_x86_64.zip",
                search_file = "ctrtool",
                install_name = "CtrTool",
                install_dir = programs.GetProgramInstallDir("CtrTool", "linux"),
                install_files = ["ctrtool"],
                release_type = config.release_type_archive,
                chmod_files = [
                    {
                        "file": "ctrtool",
                        "perms": 755
                    }
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup CtrTool")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):
        pass
