# Imports
import os, os.path
import sys

# Local imports
import config
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
    if isinstance(branchid, str) and len(branchid):
        download_cmd += [
            "-beta", branchid
        ]
    if isinstance(login, str) and len(login):
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

    # Check result
    return os.path.exists(output_dir)

# Get game info
def GetGameInfo(appid, branchid, verbose = False, exit_on_failure = False):

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
    if isinstance(branchid, str) and len(branchid):
        game_info[config.json_key_steam_branchid] = branchid
    if "data" in steam_json:
        if appid in steam_json["data"]:
            appdata = steam_json["data"][appid]

            # Base info
            if "appid" in appdata:
                game_info[config.json_key_steam_appid] = str(appdata["appid"])
            if "_change_number" in appdata:
                game_info[config.json_key_steam_changeid] = str(appdata["_change_number"])

            # Common info
            if "common" in appdata:
                appcommon = appdata["common"]
                if "name" in appcommon:
                    game_info[config.json_key_steam_name] = str(appcommon["name"])
                if "controller_support" in appcommon:
                    game_info[config.json_key_steam_controller_support] = str(appcommon["controller_support"])
    return game_info
