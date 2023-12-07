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

# HacTool tool
class HacTool(base.ToolBase):

    # Get name
    def GetName():
        return "HacTool"

    # Get config
    def GetConfig():
        return {
            "HacTool": {
                "program": {
                    "windows": "HacTool/windows/hactool.exe",
                    "linux": "HacTool/linux/HacTool.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("HacTool", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "SciresM",
                github_repo = "hactool",
                starts_with = "hactool",
                ends_with = "win.zip",
                search_file = "hactool.exe",
                install_name = "HacTool",
                install_dir = programs.GetProgramInstallDir("HacTool", "windows"),
                install_files = ["hactool.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("HacTool", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/SciresM/hactool.git",
                output_name = "HacTool",
                output_dir = programs.GetProgramInstallDir("HacTool", "linux"),
                build_cmd = [
                    "cp", "config.mk.template", "config.mk",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/hactool", "to": "AppImage/usr/bin/hactool"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/hactool", "to": "AppRun"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)