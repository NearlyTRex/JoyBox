# Imports
import os, os.path
import sys

# Local imports
import config
import command
import programs
import gameinfo
import system
import environment
import network
import ini
import storebase

# GOG store
class GOG(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()
        self.username = ini.GetIniValue("UserData.GOG", "gog_username")
        self.platform = ini.GetIniValue("UserData.GOG", "gog_platform")
        self.includes = ini.GetIniValue("UserData.GOG", "gog_includes")
        self.excludes = ini.GetIniValue("UserData.GOG", "gog_excludes")

    # Get name
    def GetName(self):
        return "GOG"

    # Login
    def Login(
        self,
        verbose = False,
        exit_on_failure = False):

        # Get tool
        gog_tool = None
        if programs.IsToolInstalled("LGOGDownloader"):
            gog_tool = programs.GetToolProgram("LGOGDownloader")
        if not gog_tool:
            system.LogError("LGOGDownloader was not found")
            sys.exit(1)

        # Get login command
        login_cmd = [
            gog_tool,
            "--login"
        ]

        # Run login command
        code = command.RunBlockingCommand(
            cmd = login_cmd,
            options = command.CommandOptions(
                blocking_processes = [gog_tool]),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    # Fetch
    def Fetch(
        self,
        identifier,
        output_dir,
        output_name = None,
        branch = None,
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

        # Get fetch command
        fetch_cmd = [
            gog_tool,
            "--download",
            "--game=^%s$" % identifier,
            "--platform=%s" % self.platform,
            "--directory=%s" % tmp_dir_result,
            "--check-free-space",
            "--threads=1",
            "--subdir-game=.",
            "--subdir-extras=extra",
            "--subdir-dlc=dlc"
        ]
        if isinstance(self.includes, str) and len(self.includes):
            fetch_cmd += [
                "--include=%s" % self.includes
            ]
        if isinstance(self.excludes, str) and len(self.excludes):
            fetch_cmd += [
                "--exclude=%s" % self.excludes
            ]

        # Run fetch command
        code = command.RunBlockingCommand(
            cmd = fetch_cmd,
            options = command.CommandOptions(
                blocking_processes = [gog_tool]),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if (code != 0):
            system.LogError("Files were not intalled successfully")
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

        # Move fetched files
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

    # Download
    def Download(
        self,
        json_file,
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
            output_offset = environment.GetLockerGamingRomDirOffset(game_info.get_category(), game_info.get_subcategory(), game_info.get_name())
            output_dir = os.path.join(os.path.realpath(output_dir), output_offset)
        else:
            output_dir = environment.GetLockerGamingRomDir(game_info.get_category(), game_info.get_subcategory(), game_info.get_name())
        if skip_existing and system.DoesDirectoryContainFiles(output_dir):
            return True

        # Get latest gog info
        latest_gog_info = self.GetInfo(
            identifier = game_info.get_gog_appid(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Get build ids
        old_buildid = game_info.get_gog_buildid()
        new_buildid = latest_gog_info[config.json_key_gog_buildid]

        # Check if game should be fetched
        should_fetch = False
        if force or old_buildid is None or new_buildid is None:
            should_fetch = True
        elif len(old_buildid) == 0:
            should_fetch = True
        elif len(old_buildid) > 0 and len(new_buildid) == 0:
            should_fetch = True
        else:
            should_fetch = new_buildid != old_buildid

        # Fetch game
        if should_fetch:
            success = self.Fetch(
                identifier = game_info.get_gog_appname(),
                output_dir = output_dir,
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

    # Get info
    def GetInfo(
        self,
        identifier,
        branch = None,
        verbose = False,
        exit_on_failure = False):

        # Get gog url
        gog_url = "https://api.gog.com/products/%s?expand=downloads" % identifier

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
        game_info[config.json_key_gog_appid] = identifier
        if "slug" in gog_json:
            game_info[config.json_key_gog_appname] = gog_json["slug"]
        if "title" in gog_json:
            game_info[config.json_key_gog_name] = gog_json["title"].strip()
        if "downloads" in gog_json:
            appdownloads = gog_json["downloads"]
            if "installers" in appdownloads:
                appinstallers = appdownloads["installers"]
                for appinstaller in appinstallers:
                    if appinstaller["os"] == self.platform:
                        if appinstaller["version"]:
                            game_info[config.json_key_gog_buildid] = appinstaller["version"]
                        else:
                            game_info[config.json_key_gog_buildid] = "original_release"
        return game_info

    # Get versions
    def GetVersions(
        self,
        json_file,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_info = gameinfo.GameInfo(
            json_file = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Ignore non-gog games
        if game_info.get_gog_appid() == "":
            return (None, None)

        # Get latest gog info
        latest_gog_info = self.GetInfo(
            identifier = game_info.get_gog_appid(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Return versions
        local_buildid = game_info.get_gog_buildid()
        remote_buildid = latest_gog_info[config.json_key_gog_buildid]
        return (local_buildid, remote_buildid)
