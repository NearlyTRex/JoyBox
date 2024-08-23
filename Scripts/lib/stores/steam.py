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
        self.platform = ini.GetIniPathValue("UserData.Steam", "steam_platform")
        self.arch = ini.GetIniPathValue("UserData.Steam", "steam_arch")
        self.accountname = ini.GetIniValue("UserData.Steam", "steam_accountname")
        self.username = ini.GetIniValue("UserData.Steam", "steam_username")
        self.userid = ini.GetIniValue("UserData.Steam", "steam_userid")
        self.install_dir = ini.GetIniPathValue("UserData.Steam", "steam_install_dir")
        if not system.IsPathValid(self.install_dir) or not system.DoesPathExist(self.install_dir):
            raise RuntimeError("Ini file does not have a valid steam install dir")

    # Get name
    def GetName(self):
        return "Steam"

    # Get platform
    def GetPlatform(self):
        return self.platform

    # Get architecture
    def GetArchitecture(self):
        return self.arch

    # Get account name
    def GetAccountName(self):
        return self.accountname

    # Get user name
    def GetUserName(self):
        return self.username

    # Get user id
    def GetUserId(self, format_type):
        steamid = self.userid
        steamid64ident = 76561197960265728
        steamidacct = int(self.userid) - steamid64ident
        if format_type == config.steam_id_format_3l:
            steamid = "[U:1:" + str(steamidacct) + "]"
        elif format_type == config.steam_id_format_3s:
            steamid = str(steamidacct)
        elif format_type == config.steam_id_format_cl:
            steamid = "STEAM_0:"
            if steamidacct % 2 == 0:
                steamid += "0:"
            else:
                steamid += "1:"
            steamid += str(steamidacct // 2)
            return steamid
        elif format_type == config.steam_id_format_cs:
            steamid = str(steamidacct // 2)
        return steamid

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

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
            self.GetAccountName(),
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
            "-os", self.GetPlatform(),
            "-osarch", self.GetArchitecture(),
            "-dir", tmp_dir_fetch
        ]
        if isinstance(branch, str) and len(branch) and branch != "public":
            fetch_cmd += [
                "-beta", branch
            ]
        if isinstance(self.GetAccountName(), str) and len(self.GetAccountName()):
            fetch_cmd += [
                "-username", self.GetAccountName(),
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
        game_info,
        output_dir = None,
        skip_existing = False,
        force = False,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_appid = game_info.get_store_appid(config.json_key_steam)
        game_branchid = game_info.get_store_branchid(config.json_key_steam)
        game_buildid = game_info.get_store_buildid(config.json_key_steam)
        game_category = game_info.get_category()
        game_subcategory = game_info.get_subcategory()
        game_name = game_info.get_name()
        game_json_file = game_info.get_json_file()

        # Ignore invalid games
        if not self.IsValidIdentifier(game_appid):
            return True

        # Get output dir
        if output_dir:
            output_offset = environment.GetLockerGamingRomDirOffset(game_category, game_subcategory, game_name)
            output_dir = os.path.join(os.path.realpath(output_dir), output_offset)
        else:
            output_dir = environment.GetLockerGamingRomDir(game_category, game_subcategory, game_name)
        if skip_existing and system.DoesDirectoryContainFiles(output_dir):
            return True

        # Get latest steam info
        latest_steam_info = self.GetInfo(
            identifier = game_appid,
            branch = game_branchid,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Get build ids
        old_buildid = game_buildid
        new_buildid = latest_steam_info[config.json_key_store_buildid]

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
                identifier = game_appid,
                branch = game_branchid,
                output_dir = output_dir,
                output_name = "%s (%s)" % (game_name, new_buildid),
                clean_output = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

        # Update json file
        json_data = system.ReadJsonFile(
            src = game_json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        json_data[config.json_key_steam] = latest_steam_info
        success = system.WriteJsonFile(
            src = game_json_file,
            json_data = json_data,
            sort_keys = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return success

    # Update
    def Update(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_appid = game_info.get_store_appid(config.json_key_steam)
        game_branchid = game_info.get_store_branchid(config.json_key_steam)
        game_json_file = game_info.get_json_file()

        # Ignore invalid games
        if not self.IsValidIdentifier(game_appid):
            return True

        # Get latest steam info
        latest_steam_info = self.GetInfo(
            identifier = game_appid,
            branch = game_branchid,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Update json file
        json_data = system.ReadJsonFile(
            src = game_json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        json_data[config.json_key_steam] = latest_steam_info
        success = system.WriteJsonFile(
            src = game_json_file,
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
            return None

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
            return None

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
            return None

        # Build game info
        game_info = {}
        game_info[config.json_key_store_appid] = identifier
        if isinstance(branch, str) and len(branch):
            game_info[config.json_key_store_branchid] = branch
        else:
            game_info[config.json_key_store_branchid] = "public"
        if identifier in steam_json:
            appdata = steam_json[identifier]
            if "common" in appdata:
                appcommon = appdata["common"]
                if "name" in appcommon:
                    game_info[config.json_key_store_name] = str(appcommon["name"])
                if "controller_support" in appcommon:
                    game_info[config.json_key_store_controller_support] = str(appcommon["controller_support"])
            if "config" in appdata:
                appconfig = appdata["config"]
                if "installdir" in appconfig:
                    game_info[config.json_key_store_installdir] = str(appconfig["installdir"])
            if "depots" in appdata:
                appdepots = appdata["depots"]
                if "branches" in appdepots:
                    appbranches = appdepots["branches"]
                    if isinstance(branch, str) and len(branch) and branch in appbranches:
                        appbranch = appbranches[branch]
                        if "buildid" in appbranch:
                            game_info[config.json_key_store_buildid] = str(appbranch["buildid"])
                        else:
                            game_info[config.json_key_store_buildid] = "unknown"
                        if "timeupdated" in appbranch:
                            game_info[config.json_key_store_builddate] = str(appbranch["timeupdated"])

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
                        if "when" in path_info:
                            for when_info in path_info["when"]:

                                # Determine if path is relevant
                                when_os = when_info["os"] if "os" in when_info else ""
                                when_store = when_info["store"] if "store" in when_info else ""
                                is_steam_path = False
                                if (when_os == "windows" or when_os == "dos") and (when_store == "steam" or when_store == ""):
                                    is_steam_path = True
                                elif when_store == "steam" and when_os == "":
                                    is_steam_path = True
                                if not is_steam_path:
                                    continue

                                # Replace tokens to get new path
                                new_location = path_location
                                new_location = new_location.replace("<winPublic>", config.token_user_public_dir)
                                new_location = new_location.replace("<winDir>", "%s/AppData/Local/VirtualStore" % config.token_user_profile_dir)
                                new_location = new_location.replace("<winAppData>", "%s/AppData/Roaming" % config.token_user_profile_dir)
                                new_location = new_location.replace("<winLocalAppData>", "%s/AppData/Local" % config.token_user_profile_dir)
                                new_location = new_location.replace("<winProgramData>", "%s/AppData/Local/VirtualStore" % config.token_user_profile_dir)
                                new_location = new_location.replace("<winDocuments>", "%s/Documents" % config.token_user_profile_dir)
                                new_location = new_location.replace("<home>", config.token_user_profile_dir)
                                new_location = new_location.replace("<root>", config.token_store_install_dir)
                                if config.json_key_store_installdir in game_info:
                                    new_location = new_location.replace("<base>", "%s/steamapps/common/%s" %
                                        (config.token_store_install_dir, game_info[config.json_key_store_installdir]))
                                new_location = new_location.replace("<storeUserId>", config.token_store_user_id)

                                # Determine if path should be saved
                                should_save_path = True
                                for path in paths:
                                    if path.startswith(new_location):
                                        should_save_path = False
                                if not should_save_path:
                                    continue

                                # Save path
                                paths.append(new_location)
                if "registry" in manifest_data:
                    for key in manifest_data["registry"]:
                        keys.append(key)
                if len(paths):
                    game_info[config.json_key_store_paths] = paths
                if len(keys):
                    game_info[config.json_key_store_keys] = keys

        # Return game info
        return game_info

    # Get versions
    def GetVersions(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_appid = game_info.get_store_appid(config.json_key_steam)
        game_branchid = game_info.get_store_branchid(config.json_key_steam)
        game_buildid = game_info.get_store_buildid(config.json_key_steam)

        # Ignore invalid games
        if not self.IsValidIdentifier(game_appid):
            return (None, None)

        # Get latest steam info
        latest_steam_info = self.GetInfo(
            identifier = game_appid,
            branch = game_branchid,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Return versions
        local_buildid = game_buildid
        remote_buildid = latest_steam_info[config.json_key_store_buildid]
        return (local_buildid, remote_buildid)

    # Get save paths
    def GetSavePaths(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_appid = game_info.get_store_appid(config.json_key_steam)
        game_paths = game_info.get_store_paths(config.json_key_steam)

        # Get user info
        user_id64 = self.GetUserId(config.steam_id_format_64)
        user_id3 = self.GetUserId(config.steam_id_format_3s)
        user_idc = self.GetUserId(config.steam_id_format_cs)

        # Ignore invalid games
        if not self.IsValidIdentifier(game_appid):
            return []

        # Build translation map
        translation_map = {}
        translation_map[config.token_user_public_dir] = []
        translation_map[config.token_user_public_dir].append("C:\\Users\\Public")
        translation_map[config.token_user_public_dir].append(os.path.join(self.install_dir, "steamapps", "compatdata", game_appid, "pfx", "drive_c", "users", "Public"))
        translation_map[config.token_user_profile_dir] = []
        if "USERPROFILE" in os.environ:
            translation_map[config.token_user_profile_dir].append(os.environ["USERPROFILE"])
        translation_map[config.token_user_profile_dir].append(os.path.join(self.install_dir, "steamapps", "compatdata", game_appid, "pfx", "drive_c", "users", "steamuser"))
        translation_map[config.token_store_install_dir] = []
        translation_map[config.token_store_install_dir].append(self.install_dir)

        # Translate save paths
        translated_paths = []
        for path in game_paths:
            for base_key in translation_map.keys():
                for key_replacement in translation_map[base_key]:

                    # Get potential full paths
                    fullpath = path.replace(base_key, key_replacement)
                    fullpath_id64 = fullpath.replace(config.token_store_user_id, self.GetUserId(config.steam_id_format_64))
                    fullpath_id3s = fullpath.replace(config.token_store_user_id, self.GetUserId(config.steam_id_format_3s))
                    fullpath_idcs = fullpath.replace(config.token_store_user_id, self.GetUserId(config.steam_id_format_cs))

                    # Create translation entry
                    entry = {}

                    # Set full path
                    if os.path.exists(fullpath):
                        entry["full"] = fullpath
                    elif os.path.exists(fullpath_id64):
                        entry["full"] = fullpath_id64
                    elif os.path.exists(fullpath_id3s):
                        entry["full"] = fullpath_id3s
                    elif os.path.exists(fullpath_idcs):
                        entry["full"] = fullpath_idcs

                    # Set relative path
                    if base_key == config.token_user_profile_dir:
                        entry["relative"] = path.replace(base_key + config.os_pathsep, "")
                    elif base_key == config.token_user_public_dir:
                        entry["relative"] = path.replace(base_key, config.computer_public_folder)
                    elif base_key == config.token_store_install_dir:
                        entry["relative"] = path.replace(base_key, config.computer_store_folder)

                    # Add entry
                    if "full" in entry and "relative" in entry:
                        translated_paths.append(entry)
        return translated_paths

    # Export save
    def ExportSave(
        self,
        game_info,
        output_dir,
        verbose = False,
        exit_on_failure = False):

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Copy save files
        for save_path_entry in self.GetSavePaths(
            game_info = game_info,
            verbose = verbose,
            exit_on_failure = exit_on_failure):
            save_src = save_path_entry["full"]
            save_dest = os.path.join(tmp_dir_result, save_path_entry["relative"])
            if os.path.exists(save_src):
                system.CopyContents(
                    src = save_src,
                    dest = save_dest,
                    show_progress = True,
                    skip_existing = True,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

        # Delete temporary directory
        system.RemoveDirectory(tmp_dir_result, verbose = verbose)
        return True

    # Import save
    def ImportSave(
        self,
        game_info,
        input_dir,
        verbose = False,
        exit_on_failure = False):
        pass
