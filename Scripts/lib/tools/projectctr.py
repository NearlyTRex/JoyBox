# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import network
import programs

# Local imports
from . import base

# ProjectCTR tool
class ProjectCTR(base.ToolBase):

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

    # Download
    def Download(self, force_downloads = False):

        # CtrMakeRom
        if force_downloads or programs.ShouldProgramBeInstalled("CtrMakeRom", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "makerom",
                ends_with = "win_x86_64.zip",
                search_file = "makerom.exe",
                install_name = "CtrMakeRom",
                install_dir = programs.GetProgramInstallDir("CtrMakeRom", "windows"),
                install_files = ["makerom.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("CtrMakeRom", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "makerom",
                ends_with = "ubuntu_x86_64.zip",
                search_file = "makerom",
                install_name = "CtrMakeRom",
                install_dir = programs.GetProgramInstallDir("CtrMakeRom", "linux"),
                install_files = ["makerom"],
                chmod_files = [
                    {
                        "file": "makerom",
                        "perms": 755
                    }
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

        # CtrTool
        if force_downloads or programs.ShouldProgramBeInstalled("CtrTool", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "ctrtool",
                ends_with = "win_x64.zip",
                search_file = "ctrtool.exe",
                install_name = "CtrTool",
                install_dir = programs.GetProgramInstallDir("CtrTool", "windows"),
                install_files = ["ctrtool.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("CtrTool", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "3DSGuy",
                github_repo = "Project_CTR",
                starts_with = "ctrtool",
                ends_with = "ubuntu_x86_64.zip",
                search_file = "ctrtool",
                install_name = "CtrTool",
                install_dir = programs.GetProgramInstallDir("CtrTool", "linux"),
                install_files = ["ctrtool"],
                chmod_files = [
                    {
                        "file": "ctrtool",
                        "perms": 755
                    }
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
