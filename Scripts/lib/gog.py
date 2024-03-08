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

# Download game
def DownloadGameByName(
    appname,
    output_dir,
    platform,
    include = "",
    exclude = "",
    clean_output = False,
    verbose = False,
    exit_on_failure = False):

    # Get tool
    gog_tool = None
    if programs.IsToolInstalled("LGOGDownloader"):
        gog_tool = programs.GetToolProgram("LGOGDownloader")
    if not gog_tool:
        system.LogError("LGOGDownloader was not found")
        sys.exit(1)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get temporary paths
    tmp_dir_extra = os.path.join(tmp_dir_result, "extra")
    tmp_dir_dlc = os.path.join(tmp_dir_result, "dlc")
    tmp_dir_dlc_extra = os.path.join(tmp_dir_dlc, "extra")

    # Get download command
    download_cmd = [
        gog_tool,
        "--download",
        "--game=^%s$" % appname,
        "--platform=%s" % platform,
        "--directory=%s" % tmp_dir_result,
        "--check-free-space",
        "--threads=1",
        "--subdir-game=.",
        "--subdir-extras=extra",
        "--subdir-dlc=dlc"
    ]
    if isinstance(include, str) and len(include):
        download_cmd += [
            "--include=%s" % include
        ]
    if isinstance(exclude, str) and len(exclude):
        download_cmd += [
            "--exclude=%s" % exclude
        ]

    # Run download command
    code = command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            blocking_processes = [gog_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if (code != 0):
        system.LogError("Files were not downloaded successfully")
        return False

    # Move dlc extra into main extra
    if system.DoesDirectoryContainFiles(tmp_dir_dlc_extra):
        system.MoveContents(
            src = tmp_dir_dlc_extra,
            dest = tmp_dir_extra,
            skip_existing = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        system.RemoveDirectory(
            dir = tmp_dir_dlc_extra,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Clean output
    if clean_output:
        system.RemoveDirectoryContents(
            dir = output_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Move downloaded files
    success = system.MoveContents(
        src = tmp_dir_result,
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
    output_dir = None,
    skip_existing = False,
    force = False,
    verbose = False,
    exit_on_failure = False):

    # Get game info
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Ignore non-gog games
    if game_info.get_gog_appid() == "":
        return True

    # Get output dir
    if output_dir:
        output_offset = environment.GetRomDirOffset(game_info.get_category(), game_info.get_subcategory(), game_info.get_name())
        output_dir = os.path.join(os.path.realpath(output_dir), output_offset)
    else:
        output_dir = environment.GetRomDir(game_info.get_category(), game_info.get_subcategory(), game_info.get_name())
    if skip_existing and system.DoesDirectoryContainFiles(output_dir):
        return True

    # Get latest gog info
    latest_gog_info = GetGameInfo(
        appid = game_info.get_gog_appid(),
        platform = platform,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get build ids
    old_buildid = game_info.get_gog_buildid()
    new_buildid = latest_gog_info[config.json_key_gog_buildid]

    # Check if game should be downloaded
    should_download = False
    if force:
        should_download = True
    elif len(old_buildid) == 0:
        should_download = True
    elif len(old_buildid) > 0 and len(new_buildid) == 0:
        should_download = True
    else:
        should_download = new_buildid != old_buildid
    if not should_download:
        return True

    # Download game
    success = DownloadGameByName(
        appname = game_info.get_gog_appname(),
        output_dir = output_dir,
        platform = platform,
        include = "i,e",
        clean_output = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Update json file
    json_data = system.ReadJsonFile(
        src = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    json_data[config.json_key_gog] = latest_gog_info
    success = system.WriteJsonFile(
        src = json_file,
        json_data = json_data,
        sort_keys = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return success

# Check game by json file
def CheckGameByJsonFile(
    json_file,
    platform,
    verbose = False,
    exit_on_failure = False):

    # Get game info
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Ignore non-gog games
    if game_info.get_gog_appid() == "":
        return True

    # Get latest gog info
    latest_gog_info = GetGameInfo(
        appid = game_info.get_gog_appid(),
        platform = platform,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get build ids
    old_buildid = game_info.get_gog_buildid()
    new_buildid = latest_gog_info[config.json_key_gog_buildid]

    # Check if game is out of date
    if new_buildid != old_buildid:
        system.LogWarning("Game '%s' is out of date! Local = '%s', remote = '%s'" % (game_info.get_name(), old_buildid, new_buildid))
    return True

# Get game info
def GetGameInfo(appid, platform, verbose = False, exit_on_failure = False):

    # Get gog url
    gog_url = "https://api.gog.com/products/%s?expand=downloads" % appid

    # Get gog json
    gog_json = network.GetRemoteJson(
        url = gog_url,
        headers = {"Accept": "application/json"},
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not gog_json:
        system.LogError("Unable to find gog release information from '%s'" % gog_url)
        return False

    # Build game info
    game_info = {}
    game_info[config.json_key_gog_appid] = appid
    if "slug" in gog_json:
        game_info[config.json_key_gog_appname] = gog_json["slug"]
    if "title" in gog_json:
        game_info[config.json_key_gog_name] = gog_json["title"].strip()
    if "downloads" in gog_json:
        appdownloads = gog_json["downloads"]
        if "installers" in appdownloads:
            appinstallers = appdownloads["installers"]
            for appinstaller in appinstallers:
                if appinstaller["os"] == platform:
                    if appinstaller["version"]:
                        game_info[config.json_key_gog_buildid] = appinstaller["version"]
                    else:
                        game_info[config.json_key_gog_buildid] = "original_release"
    return game_info
