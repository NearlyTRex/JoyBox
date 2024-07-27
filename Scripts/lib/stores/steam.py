# Imports
import os, os.path
import sys

# Local imports
import config
import command
import archive
import programs
import gameinfo
import system
import environment
import ini
import storebase

# Steam store
class Steam(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()
        self.accountname = ini.GetIniValue("UserData.Steam", "steam_accountname")
        self.username = ini.GetIniValue("UserData.Steam", "steam_username")
        self.userid = ini.GetIniValue("UserData.Steam", "steam_userid")
        self.platform = ini.GetIniPathValue("UserData.Steam", "steam_platform")
        self.arch = ini.GetIniPathValue("UserData.Steam", "steam_arch")
        self.install_dir = ini.GetIniPathValue("UserData.Steam", "steam_install_dir")

    # Get name
    def GetName(self):
        return "Steam"

    # Login
    def Login(
        self,
        verbose = False,
        exit_on_failure = False):

        # Get tool
        steam_tool = None
        if programs.IsToolInstalled("SteamCMD"):
            steam_tool = programs.GetToolProgram("SteamCMD")
        if not steam_tool:
            system.LogError("SteamCMD was not found")
            sys.exit(1)

        # Get login command
        login_cmd = [
            steam_tool,
            "+login",
            self.accountname,
            "+quit"
        ]

        # Run login command
        code = command.RunBlockingCommand(
            cmd = login_cmd,
            options = command.CommandOptions(
                blocking_processes = [steam_tool]),
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
        tmp_dir_fetch = os.path.join(tmp_dir_result, "fetch")
        tmp_dir_archive = os.path.join(tmp_dir_result, "archive")
        system.MakeDirectory(tmp_dir_fetch, verbose = verbose, exit_on_failure = exit_on_failure)
        system.MakeDirectory(tmp_dir_archive, verbose = verbose, exit_on_failure = exit_on_failure)

        # Get fetch command
        fetch_cmd = [
            steamdepot_tool,
            "-app", identifier,
            "-os", self.platform,
            "-osarch", self.arch,
            "-dir", tmp_dir_fetch
        ]
        if isinstance(branch, str) and len(branch) and branch != "public":
            fetch_cmd += [
                "-beta", branch
            ]
        if isinstance(self.accountname, str) and len(self.accountname):
            fetch_cmd += [
                "-username", self.accountname,
                "-remember-password"
            ]

        # Run fetch command
        command.RunBlockingCommand(
            cmd = fetch_cmd,
            options = command.CommandOptions(
                blocking_processes = [steamdepot_tool]),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Check that files fetched
        if system.IsDirectoryEmpty(tmp_dir_fetch):
            system.LogError("Files were not fetched successfully")
            return False

        # Archive fetched files
        success = archive.CreateArchiveFromFolder(
            archive_file = os.path.join(tmp_dir_archive, "%s.7z" % output_name),
            source_dir = tmp_dir_fetch,
            excludes = [".DepotDownloader"],
            volume_size = "4092m",
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            system.RemoveDirectory(tmp_dir_result, verbose = verbose)
            return False

        # Clean output
        if clean_output:
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

        # Ignore non-steam games
        if game_info.get_steam_appid() == "":
            return True

        # Get output dir
        if output_dir:
            output_offset = environment.GetLockerGamingRomDirOffset(game_info.get_category(), game_info.get_subcategory(), game_info.get_name())
            output_dir = os.path.join(os.path.realpath(output_dir), output_offset)
        else:
            output_dir = environment.GetLockerGamingRomDir(game_info.get_category(), game_info.get_subcategory(), game_info.get_name())
        if skip_existing and system.DoesDirectoryContainFiles(output_dir):
            return True

        # Get latest steam info
        latest_steam_info = self.GetInfo(
            identifier = game_info.get_steam_appid(),
            branch = game_info.get_steam_branchid(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Get build ids
        old_buildid = game_info.get_steam_buildid()
        new_buildid = latest_steam_info[config.json_key_steam_buildid]

        # Check if game should be fetched
        should_fetch = False
        if force or old_buildid is None or new_buildid is None:
            should_fetch = True
        elif len(old_buildid) == 0:
            should_fetch = True
        else:
            if new_buildid.isnumeric() and old_buildid.isnumeric():
                should_fetch = int(new_buildid) > int(old_buildid)

        # Fetch game
        if should_fetch:
            success = self.Fetch(
                identifier = game_info.get_steam_appid(),
                branch = game_info.get_steam_branchid(),
                output_dir = output_dir,
                output_name = "%s (%s)" % (game_info.get_name(), new_buildid),
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
        json_data[config.json_key_steam] = latest_steam_info
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
            "+app_info_print", identifier,
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
            system.LogError("Unable to find steam information for '%s'" % identifier)
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
                    if line.startswith("AppID : %s" % identifier):
                        is_vdf_line = True
            steam_json = vdf.loads(vdf_text)
        except:
            system.LogError("Unable to parse steam information for '%s'" % identifier)
            return False

        # Build game info
        game_info = {}
        game_info[config.json_key_steam_appid] = identifier
        if isinstance(branch, str) and len(branch):
            game_info[config.json_key_steam_branchid] = branch
        else:
            game_info[config.json_key_steam_branchid] = "public"
        if identifier in steam_json:
            appdata = steam_json[identifier]
            if "common" in appdata:
                appcommon = appdata["common"]
                if "name" in appcommon:
                    game_info[config.json_key_steam_name] = str(appcommon["name"])
                if "controller_support" in appcommon:
                    game_info[config.json_key_steam_controller_support] = str(appcommon["controller_support"])
            if "config" in appdata:
                appconfig = appdata["config"]
                if "installdir" in appconfig:
                    game_info[config.json_key_steam_installdir] = str(appconfig["installdir"])
            if "depots" in appdata:
                appdepots = appdata["depots"]
                if "branches" in appdepots:
                    appbranches = appdepots["branches"]
                    if isinstance(branch, str) and len(branch) and branch in appbranches:
                        appbranch = appbranches[branch]
                        if "buildid" in appbranch:
                            game_info[config.json_key_steam_buildid] = str(appbranch["buildid"])
                        if "timeupdated" in appbranch:
                            game_info[config.json_key_steam_builddate] = str(appbranch["timeupdated"])

        # Augment by manifest
        if self.manifest:
            for manifest_name, manifest_data in self.manifest.items():
                if "steam" not in manifest_data:
                    continue
                if "id" in manifest_data["steam"] and str(manifest_data["steam"]["id"]) != identifier:
                    continue
                paths = []
                keys = []
                if "files" in manifest_data:
                    for path_location, path_info in manifest_data["files"].items():
                        for when_info in path_info["when"]:
                            when_os = when_info["os"] if "os" in when_info else ""
                            when_store = when_info["store"] if "store" in when_info else ""
                            if when_os == "windows":
                                if when_store == "steam" or when_store == "":
                                    new_location = path_location
                                    new_location = new_location.replace("<winPublic>", "USERPUBLIC")
                                    new_location = new_location.replace("<winDir>", "USERPROFILE/AppData/Local/VirtualStore")
                                    new_location = new_location.replace("<winAppData>", "USERPROFILE/AppData/Roaming")
                                    new_location = new_location.replace("<winLocalAppData>", "USERPROFILE/AppData/Local")
                                    new_location = new_location.replace("<winDocuments>", "USERPROFILE/Documents")
                                    new_location = new_location.replace("<home>", "USERPROFILE")
                                    new_location = new_location.replace("<root>", "STEAMROOT")
                                    new_location = new_location.replace("<base>", "STEAMROOT/steamapps/common/%s" % game_info[config.json_key_steam_installdir])
                                    new_location = new_location.replace("<storeUserId>", "STEAMUSERID")
                                    paths.append(new_location)
                if "registry" in manifest_data:
                    for key in manifest_data["registry"]:
                        keys.append(key)
                if len(paths):
                    game_info[config.json_key_steam_paths] = paths
                if len(keys):
                    game_info[config.json_key_steam_keys] = keys

        # Return game info
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

        # Ignore non-steam games
        if game_info.get_steam_appid() == "":
            return (None, None)

        # Get latest steam info
        latest_steam_info = self.GetInfo(
            identifier = game_info.get_steam_appid(),
            branch = game_info.get_steam_branchid(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Return versions
        local_buildid = game_info.get_steam_buildid()
        remote_buildid = latest_steam_info[config.json_key_steam_buildid]
        return (local_buildid, remote_buildid)
