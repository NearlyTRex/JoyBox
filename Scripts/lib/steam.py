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
import environment

# Download game by id
def DownloadGameByID(
    appid,
    branchid,
    output_dir,
    output_name,
    platform,
    arch,
    login,
    clean_output_first = False,
    verbose = False,
    exit_on_failure = False):

    # Get tool
    steamdepot_tool = None
    if programs.IsToolInstalled("SteamDepotDownloader"):
        steamdepot_tool = programs.GetToolProgram("SteamDepotDownloader")
    if not steamdepot_tool:
        system.LogError("SteamDepotDownloader was not found")
        sys.exit(1)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Make temporary dirs
    tmp_dir_download = os.path.join(tmp_dir_result, "download")
    tmp_dir_archive = os.path.join(tmp_dir_result, "archive")
    system.MakeDirectory(tmp_dir_download, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(tmp_dir_archive, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get download command
    download_cmd = [
        steamdepot_tool,
        "-app", appid,
        "-os", platform,
        "-osarch", arch,
        "-dir", tmp_dir_download
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
            blocking_processes = [steamdepot_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check that files downloaded
    if system.IsDirectoryEmpty(tmp_dir_download):
        system.LogError("Files were not downloaded successfully")
        return False

    # Archive downloaded files
    success = archive.CreateArchiveFromFolder(
        archive_file = os.path.join(tmp_dir_archive, "%s.7z" % output_name),
        source_dir = tmp_dir_download,
        excludes = [".DepotDownloader"],
        volume_size = "4092m",
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        system.RemoveDirectory(tmp_dir_result, verbose = verbose)
        return False

    # Clean output first
    if clean_output_first:
        system.RemoveDirectoryContents(
            dir = output_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Move archived files
    success = system.MoveContents(
        src = tmp_dir_archive,
        dest = output_dir,
        show_progress = True,
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
def DownloadGameByJsonFile(
    json_file,
    platform,
    arch,
    login,
    force_download = False,
    verbose = False,
    exit_on_failure = False):

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
    success = DownloadGameByID(
        appid = game_info.get_steam_appid(),
        branchid = game_info.get_steam_branchid(),
        output_dir = environment.GetRomDir(game_info.get_category(), game_info.get_subcategory(), game_info.get_name()),
        output_name = game_info.get_name(),
        platform = platform,
        arch = arch,
        login = login,
        clean_output_first = True,
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

    # Get tool
    steamcmd_tool = None
    if programs.IsToolInstalled("SteamCMD"):
        steamcmd_tool = programs.GetToolProgram("SteamCMD")
    if not steamcmd_tool:
        system.LogError("SteamCMD was not found")
        return False

    # Get info command
    info_cmd = [
        steamcmd_tool,
        "+login", "anonymous",
        "+app_info_print", appid,
        "+quit"
    ]

    # Run info command
    info_output = command.RunOutputCommand(
        cmd = info_cmd,
        options = command.CommandOptions(
            blocking_processes = [steamcmd_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if len(info_output) == 0:
        system.LogError("Unable to find steam information for '%s'" % appid)
        return False

    # Get steam json
    steam_json = {}
    try:
        import vdf
        vdf_text = ""
        is_vdf_line = False
        for line in info_output.split("\n"):
            if is_vdf_line:
                vdf_text += line + "\n"
            else:
                if line.startswith("AppID : %s" % appid):
                    is_vdf_line = True
        steam_json = vdf.loads(vdf_text)
    except:
        system.LogError("Unable to parse steam information for '%s'" % appid)
        return False

    # Build game info
    game_info = {}
    if isinstance(branchid, str) and len(branchid):
        game_info[config.json_key_steam_branchid] = branchid
    else:
        game_info[config.json_key_steam_branchid] = "public"
    if appid in steam_json:
        appdata = steam_json[appid]
        if "common" in appdata:
            appcommon = appdata["common"]
            if "name" in appcommon:
                game_info[config.json_key_steam_name] = str(appcommon["name"])
            if "controller_support" in appcommon:
                game_info[config.json_key_steam_controller_support] = str(appcommon["controller_support"])
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
