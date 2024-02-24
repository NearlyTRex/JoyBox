# Imports
import os, os.path
import sys

# Local imports
import command
import archive
import programs
import network
import system

# Download game
def DownloadGame(appid, branchid, output_dir, output_name, platform, arch, login, verbose = False, exit_on_failure = False):

    # Get tool
    steam_tool = None
    if programs.IsToolInstalled("SteamDepotDownloader"):
        steam_tool = programs.GetToolProgram("SteamDepotDownloader")
    if not steam_tool:
        system.LogError("SteamDepotDownloader was not found")
        sys.exit(1)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get download command
    download_cmd = [
        steam_tool,
        "-app", appid,
        "-os", platform,
        "-osarch", arch,
        "-dir", tmp_dir_result
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

    # Archive downloaded files
    success = archive.CreateArchiveFromFolder(
        archive_file = os.path.join(output_dir, "%s.7z" % output_name),
        source_dir = tmp_dir_result,
        excludes = [".DepotDownloader"],
        volume_size = "4092m",
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Write game info
    success = system.WriteJsonFile(
        src = os.path.join(output_dir, "%s.json" % output_name),
        json_data = GetGameInfo(appid),
        sort_keys = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check result
    return os.path.exists(output_dir)

# Get game info
def GetGameInfo(appid, verbose = False, exit_on_failure = False):

    # Get steam url
    steam_url = "https://api.steamcmd.net/v1/info/%s" % appid

    # Get steam json
    steam_json = network.GetRemoteJson(
        url = steam_url,
        headers = {"Accept": "application/json"},
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not steam_json:
        system.LogError("Unable to find steam release information from '%s'" % steam_url)
        return False

    # Parse game info
    game_info = {}
    game_info["appid"] = appid
    if "data" in steam_json:
        if appid in steam_json["data"]:
            if "_change_number" in steam_json["data"][appid]:
                game_info["change_number"] = str(steam_json["data"][appid]["_change_number"])
    return game_info
