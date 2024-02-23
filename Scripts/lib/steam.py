# Imports
import os, os.path
import sys

# Local imports
import command
import programs
import system

# Download game
def DownloadGame(appid, branchid, output_dir, platform, arch, login, verbose = False, exit_on_failure = False):

    # Get tool
    steam_tool = None
    if programs.IsToolInstalled("SteamDepotDownloader"):
        steam_tool = programs.GetToolProgram("SteamDepotDownloader")
    if not steam_tool:
        system.LogError("SteamDepotDownloader was not found")
        sys.exit(1)

    # Get download command
    download_cmd = [
        steam_tool,
        "-app", appid,
        "-os", platform,
        "-osarch", arch,
        "-dir", output_dir
    ]
    if branchid:
        download_cmd += [
            "-beta", branchid
        ]
    if login:
        download_cmd += [
            "-username", login,
            "-remember-password"
        ]

    # Run download command
    command.RunCheckedCommand(
        cmd = download_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
