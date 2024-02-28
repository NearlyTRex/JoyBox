# Imports
import os, os.path
import sys

# Local imports
import config
import command
import archive
import programs
import network
import gameinfo
import system

# Download game by id
def DownloadGameByID(appid, branchid, output_dir, output_name, platform, arch, login, verbose = False, exit_on_failure = False):

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
    if isinstance(branchid, str) and len(branchid) and branchid != "public":
        download_cmd += [
            "-beta", branchid
        ]
    if isinstance(login, str) and len(login):
        download_cmd += [
            "-username", login,
            "-remember-password"
        ]

    # Run download command
    command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            blocking_processes = [steam_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check that files downloaded
    if system.IsDirectoryEmpty(tmp_dir_result):
        system.LogError("Files were not downloaded successfully")
        return False

    # Archive downloaded files
    success = archive.CreateArchiveFromFolder(
        archive_file = os.path.join(output_dir, "%s.7z" % output_name),
        source_dir = tmp_dir_result,
        excludes = [".DepotDownloader"],
        volume_size = "4092m",
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        system.RemoveDirectory(tmp_dir_result, verbose = verbose)
        return False

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Check result
    return os.path.exists(output_dir)

# Download game by json file
def DownloadGameByJsonFile(json_file, output_dir, platform, arch, login, force_download = False, verbose = False, exit_on_failure = False):

    # Get game info
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Ignore non-steam games
    if game_info.get_steam_appid() == "":
        return False

    # Get latest steam info
    latest_steam_info = GetGameInfo(
        appid = game_info.get_steam_appid(),
        branchid = game_info.get_steam_branchid(),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check if game should be downloaded
    should_download = False
    if force_download:
        should_download = True
    elif game_info.get_steam_buildid() == "":
        should_download = True
    else:
        old_buildid = game_info.get_steam_buildid()
        new_buildid = latest_steam_info[config.json_key_steam_buildid]
        if new_buildid.isnumeric() and old_buildid.isnumeric():
            should_download = int(new_buildid) > int(old_buildid)
    if not should_download:
        return False

    # Download game
    success = steam.DownloadGameByID(
        appid = game_info.get_steam_appid(),
        branchid = game_info.get_steam_branchid(),
        output_dir = os.path.join(output_dir, game_info.get_name()),
        output_name = game_info.get_name(),
        platform = platform,
        arch = arch,
        login = login,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Update json file
    json_data = system.ReadJsonFile(
        src = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    json_data[config.json_key_steam] = latest_steam_info
    success = system.WriteJsonFile(
        src = json_file,
        json_data = json_data,
        sort_keys = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return success

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
    else:
        game_info[config.json_key_steam_branchid] = "public"
    if "data" in steam_json:
        if appid in steam_json["data"]:
            appdata = steam_json["data"][appid]

            # Base info
            if "appid" in appdata:
                game_info[config.json_key_steam_appid] = str(appdata["appid"])

            # Common info
            if "common" in appdata:
                appcommon = appdata["common"]
                if "name" in appcommon:
                    game_info[config.json_key_steam_name] = str(appcommon["name"])
                if "controller_support" in appcommon:
                    game_info[config.json_key_steam_controller_support] = str(appcommon["controller_support"])

            # Depots info
            if "depots" in appdata:
                appdepots = appdata["depots"]
                if "branches" in appdepots:
                    appbranches = appdepots["branches"]
                    if isinstance(branchid, str) and len(branchid) and branchid in appbranches:
                        appbranch = appbranches[branchid]
                        if "buildid" in appbranch:
                            game_info[config.json_key_steam_buildid] = str(appbranch["buildid"])
                        if "timeupdated" in appbranch:
                            game_info[config.json_key_steam_builddate] = str(appbranch["timeupdated"])
    return game_info
