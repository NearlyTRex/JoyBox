# Imports
import os, os.path
import sys

# Local imports
import config
import command
import archive
import programs
import system
import network
import ini
import jsondata
import collection
import webpage
import storebase
import metadataentry
import metadatacollector

# Steam store
class Steam(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get platform / architecture
        self.platform = ini.GetIniPathValue("UserData.Steam", "steam_platform")
        self.arch = ini.GetIniPathValue("UserData.Steam", "steam_arch")
        if not self.platform or not self.arch:
            raise RuntimeError("Ini file does not have a valid steam platform/arch")

        # Get account name
        self.accountname = ini.GetIniValue("UserData.Steam", "steam_accountname")
        if not self.accountname:
            raise RuntimeError("Ini file does not have a valid steam account")

        # Get user details
        self.username = ini.GetIniValue("UserData.Steam", "steam_username")
        self.userid = ini.GetIniValue("UserData.Steam", "steam_userid")
        if not self.username or not self.userid:
            raise RuntimeError("Ini file does not have a valid steam user details")

        # Get web api key
        self.web_api_key = ini.GetIniValue("UserData.Steam", "steam_web_api_key")
        if not self.web_api_key:
            raise RuntimeError("Ini file does not have a valid steam web api key")

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Steam", "steam_install_dir")
        if not system.IsPathValid(self.install_dir) or not system.DoesPathExist(self.install_dir):
            raise RuntimeError("Ini file does not have a valid steam install dir")

    # Get name
    def GetName(self):
        return "Steam"

    # Get type
    def GetType(self):
        return config.StoreType.STEAM

    # Get platform
    def GetPlatform(self):
        return config.platform_computer_steam

    # Get category
    def GetCategory(self):
        return config.game_category_computer

    # Get subcategory
    def GetSubcategory(self):
        return config.game_subcategory_steam

    # Get key
    def GetKey(self):
        return config.json_key_steam

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.StoreIdentifierType.METADATA:
            return json_wrapper.get_value(config.json_key_store_appurl)
        return json_wrapper.get_value(config.json_key_store_appid)

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
        if format_type == config.SteamIDFormatType.STEAMID_3L:
            steamid = "[U:1:" + str(steamidacct) + "]"
        elif format_type == config.SteamIDFormatType.STEAMID_3S:
            steamid = str(steamidacct)
        elif format_type == config.SteamIDFormatType.STEAMID_CL:
            steamid = "STEAM_0:"
            if steamidacct % 2 == 0:
                steamid += "0:"
            else:
                steamid += "1:"
            steamid += str(steamidacct // 2)
            return steamid
        elif format_type == config.SteamIDFormatType.STEAMID_CS:
            steamid = str(steamidacct // 2)
        return steamid

    # Get web api key
    def GetWebApiKey(self):
        return self.web_api_key

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    ############################################################

    # Login
    def Login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        steam_tool = None
        if programs.IsToolInstalled("SteamCMD"):
            steam_tool = programs.GetToolProgram("SteamCMD")
        if not steam_tool:
            system.LogErrorAndQuit("SteamCMD was not found")

        # Get login command
        login_cmd = [
            steam_tool,
            "+login", self.GetAccountName(),
            "+quit"
        ]

        # Run login command
        code = command.RunBlockingCommand(
            cmd = login_cmd,
            options = command.CommandOptions(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################

    # Get purchases
    def GetPurchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get steam url
        steam_url = "https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/"
        steam_url += "?key=%s" % self.GetWebApiKey()
        steam_url += "&steamid=%s" % self.GetUserId(config.SteamIDFormatType.STEAMID_64)
        steam_url += "&include_appinfo=true"
        steam_url += "&include_played_free_games=true"
        steam_url += "&format=json"
        if not network.IsUrlReachable(steam_url):
            return None

        # Get steam json
        steam_json = network.GetRemoteJson(
            url = steam_url,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not steam_json:
            system.LogError("Unable to find steam release information from '%s'" % steam_url)
            return None

        # Parse json
        purchases = []
        if "response" in steam_json:
            if "games" in steam_json["response"]:
                for entry in steam_json["response"]["games"]:

                    # Gather info
                    line_appid = str(entry["appid"])
                    line_title = entry["name"]
                    line_keys = []
                    line_paths = [
                        os.path.join(config.token_store_install_dir, "userdata", config.token_store_user_id, line_appid)
                    ]

                    # Create purchase
                    purchase = jsondata.JsonData(
                        json_data = {},
                        json_platform = self.GetPlatform())
                    purchase.set_value(config.json_key_store_appid, line_appid)
                    purchase.set_value(config.json_key_store_appurl, self.GetLatestUrl(line_appid))
                    purchase.set_value(config.json_key_store_name, line_title)
                    purchase.set_value(config.json_key_store_branchid, config.steam_branch_format_public)
                    purchase.set_value(config.json_key_store_keys, line_keys)
                    purchase.set_value(config.json_key_store_paths, line_paths)
                    purchases.append(purchase)
        return purchases

    ############################################################

    # Get latest jsondata
    def GetLatestJsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidIdentifier(identifier):
            return None

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
            pretend_run = pretend_run,
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
        except Exception as e:
            system.LogError(e)
            system.LogError("Unable to parse steam information for '%s'" % identifier)
            system.LogError("Received output:\n%s" % info_output)
            return None

        # Build game info
        game_info = {}
        game_info[config.json_key_store_appid] = identifier
        game_info[config.json_key_store_appurl] = self.GetLatestUrl(identifier)
        game_info[config.json_key_store_paths] = []
        game_info[config.json_key_store_keys] = []
        if isinstance(branch, str) and len(branch):
            game_info[config.json_key_store_branchid] = branch
        else:
            game_info[config.json_key_store_branchid] = "public"

        # Add standard steam paths
        game_info[config.json_key_store_paths] += [
            os.path.join(config.token_store_install_dir, "userdata", config.token_store_user_id, identifier)
        ]

        # Augment by json
        if identifier in steam_json:
            appdata = steam_json[identifier]
            if "common" in appdata:
                appcommon = appdata["common"]
                if "name" in appcommon:
                    game_info[config.json_key_store_name] = str(appcommon["name"]).strip()
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

                # Skip games that are not present
                if "steam" not in manifest_data:
                    continue
                if "id" in manifest_data["steam"] and str(manifest_data["steam"]["id"]) != identifier:
                    continue

                # Get existing paths and keys
                game_paths = set(game_info[config.json_key_store_paths])
                game_keys = set(game_info[config.json_key_store_keys])

                # Examine manifest file data
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

                                # Get base path
                                base_path = None
                                if config.json_key_store_installdir in game_info:
                                    base_path = "steamapps/common/%s" % game_info[config.json_key_store_installdir]

                                # Save path
                                game_paths.add(storebase.TranslateStorePath(path_location, base_path))

                # Examine manifest registry data
                if "registry" in manifest_data:
                    for key in manifest_data["registry"]:
                        game_keys.add(key)

                # Clean and save paths
                game_info[config.json_key_store_paths] = system.SortStrings(game_paths)

                # Save keys
                game_info[config.json_key_store_keys] = system.SortStrings(game_keys)

        # Return game info
        return jsondata.JsonData(game_info, self.GetPlatform())

    ############################################################

    # Get latest metadata
    def GetLatestMetadata(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidIdentifier(identifier):
            return None

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Load url
        success = webpage.LoadUrl(web_driver, identifier)
        if not success:
            return None

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()
        metadata_entry.set_url(identifier)

        # Look for game description
        element_game_description = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"id": "aboutThisGame"}),
            verbose = verbose)
        if element_game_description:
            raw_game_description = webpage.GetElementChildrenText(element_game_description)
            if raw_game_description:
                description_text = raw_game_description
                description_text = system.TrimSubstringFromStart(description_text, "About This Game")
                description_text = system.TrimSubstringFromStart(description_text, "About This Software")
                description_text = system.TrimSubstringFromStart(description_text, "About This Demo")
                metadata_entry.set_description(description_text)

        # Look for game details
        element_game_details = webpage.GetElement(
            parent = web_driver,
            locator = webpage.ElementLocator({"id": "genresAndManufacturer"}))
        if element_game_details:

            # Grab the information text
            raw_game_details = webpage.GetElementText(element_game_details)
            for game_detail_line in raw_game_details.split("\n"):

                # Release
                if system.DoesStringStartWithSubstring(game_detail_line, "Release Date:"):
                    release_text = system.TrimSubstringFromStart(game_detail_line, "Release Date:").strip()
                    release_text = system.ConvertDateString(release_text, "%b %d, %Y", "%Y-%m-%d")
                    metadata_entry.set_release(release_text)

                # Developer
                elif system.DoesStringStartWithSubstring(game_detail_line, "Developer:"):
                    developer_text = system.TrimSubstringFromStart(game_detail_line, "Developer:").strip()
                    metadata_entry.set_developer(developer_text)

                # Publisher
                elif system.DoesStringStartWithSubstring(game_detail_line, "Publisher:"):
                    publisher_text = system.TrimSubstringFromStart(game_detail_line, "Publisher:").strip()
                    metadata_entry.set_publisher(publisher_text)

                # Genre
                elif system.DoesStringStartWithSubstring(game_detail_line, "Genre:"):
                    genre_text = system.TrimSubstringFromStart(game_detail_line, "Genre:").strip().replace(", ", ";")
                    metadata_entry.set_genre(genre_text)

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Return metadata entry
        return metadata_entry

    ############################################################

    # Get latest url
    def GetLatestUrl(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidIdentifier(identifier):
            return None

        # Return latest url
        latest_url = "https://store.steampowered.com/app/%s" % identifier
        return latest_url

    ############################################################

    # Get latest asset url
    def GetLatestAssetUrl(
        self,
        identifier,
        asset_type,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidIdentifier(identifier):
            return None

        # Latest asset url
        latest_asset_url = None

        # BoxFront
        if asset_type == config.AssetType.BOXFRONT:
            latest_asset_url = "https://cdn.cloudflare.steamstatic.com/steam/apps/%s/library_600x900_2x.jpg" % identifier

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = webpage.GetMatchingUrl(
                url = self.GetLatestUrl(identifier),
                base_url = "https://video.fastly.steamstatic.com/store_trailers",
                starts_with = "https://video.fastly.steamstatic.com/store_trailers",
                ends_with = ".mp4",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Return latest asset url
        return latest_asset_url

    ############################################################

    # Get game save paths
    def GetGameSavePaths(
        self,
        game_info,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get game info
        game_appid = game_info.get_store_appid(self.GetKey())
        game_paths = game_info.get_store_paths(self.GetKey())

        # Check if path should be added
        def ShouldAddPath(path, base, variant):
            parts = system.SplitFilePath(path, base)
            if len(parts) != 2:
                return False
            return system.IsPathFileOrDirectory(os.path.join(parts[0], variant))

        # Add alternate paths
        for path in sorted(game_paths):
            for appdata_base in config.appdata_variants.keys():
                if appdata_base in path:
                    for appdata_variant in config.appdata_variants[appdata_base]:
                        if ShouldAddPath(path, appdata_base, appdata_variant):
                            game_paths.append(path.replace(appdata_base, appdata_variant))

        # Get user info
        user_id64 = self.GetUserId(config.SteamIDFormatType.STEAMID_64)
        user_id3 = self.GetUserId(config.SteamIDFormatType.STEAMID_3S)
        user_idc = self.GetUserId(config.SteamIDFormatType.STEAMID_CS)

        # Ignore invalid identifier
        if not self.IsValidIdentifier(game_appid):
            return []

        # Build translation map
        translation_map = {}
        translation_map[config.token_user_registry_dir] = []
        translation_map[config.token_user_registry_dir].append(os.path.join(self.install_dir, "steamapps", "compatdata", game_appid, "pfx"))
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

                    # Get potential user ids
                    userid_64 = self.GetUserId(config.SteamIDFormatType.STEAMID_64)
                    userid_3s = self.GetUserId(config.SteamIDFormatType.STEAMID_3S)
                    userid_cs = self.GetUserId(config.SteamIDFormatType.STEAMID_CS)

                    # Get potential full paths
                    fullpath = path.replace(base_key, key_replacement)
                    fullpath_id64 = fullpath.replace(config.token_store_user_id, userid_64)
                    fullpath_id3s = fullpath.replace(config.token_store_user_id, userid_3s)
                    fullpath_idcs = fullpath.replace(config.token_store_user_id, userid_cs)

                    # Get potential relative paths
                    relativepath = path
                    relativepath_id64 = relativepath.replace(config.token_store_user_id, userid_64)
                    relativepath_id3s = relativepath.replace(config.token_store_user_id, userid_3s)
                    relativepath_idcs = relativepath.replace(config.token_store_user_id, userid_cs)

                    # Get potential new base paths
                    new_base_general = config.SaveType.GENERAL.camelcase
                    new_base_public = os.path.join(new_base_general, config.computer_folder_public)
                    new_base_registry = os.path.join(new_base_general, config.computer_folder_registry)
                    new_base_store = os.path.join(new_base_general, config.computer_folder_store, config.StoreType.STEAM.camelcase)

                    # Determine which paths exist
                    real_userid = None
                    real_fullpath = None
                    real_relativepath = None
                    if system.IsPathFileOrDirectory(fullpath):
                        real_userid = userid_64
                        real_fullpath = fullpath
                        real_relativepath = relativepath
                    elif system.IsPathFileOrDirectory(fullpath_id64):
                        real_userid = userid_64
                        real_fullpath = fullpath_id64
                        real_relativepath = relativepath_id64
                    elif system.IsPathFileOrDirectory(fullpath_id3s):
                        real_userid = userid_3s
                        real_fullpath = fullpath_id3s
                        real_relativepath = relativepath_id3s
                    elif system.IsPathFileOrDirectory(fullpath_idcs):
                        real_userid = userid_cs
                        real_fullpath = fullpath_idcs
                        real_relativepath = relativepath_idcs
                    if not real_userid or not real_fullpath or not real_relativepath:
                        continue

                    # Create translation entry
                    entry = {}

                    # Set full path
                    entry["full"] = real_fullpath

                    # Set relative path
                    if base_key == config.token_user_profile_dir:
                        relative_path = real_relativepath.replace(base_key, new_base_general)
                        entry["relative"] = [relative_path]
                    elif base_key == config.token_user_public_dir:
                        relative_path = real_relativepath.replace(base_key, new_base_public)
                        entry["relative"] = [relative_path]
                    elif base_key == config.token_user_registry_dir:
                        relative_path = real_relativepath.replace(base_key, new_base_registry)
                        entry["relative"] = [relative_path]
                    elif base_key == config.token_store_install_dir:
                        relative_path = real_relativepath.replace(base_key, new_base_store)
                        entry["relative"] = [relative_path]

                    # Add entry
                    if "full" in entry and "relative" in entry:
                        translated_paths.append(entry)
        return translated_paths

    ############################################################

    # Install by identifier
    def InstallByIdentifier(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        steam_tool = None
        if programs.IsToolInstalled("SteamCMD"):
            steam_tool = programs.GetToolProgram("SteamCMD")
        if not steam_tool:
            system.LogErrorAndQuit("SteamCMD was not found")

        # Get install command
        install_cmd = [
            steam_tool,
            "@sSteamCmdForcePlatformType", self.GetPlatform(),
            "+login", self.GetAccountName(),
            "app_update", identifier,
            "+quit"
        ]

        # Run install command
        code = command.RunBlockingCommand(
            cmd = install_cmd,
            options = command.CommandOptions(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################

    # Launch by identifier
    def LaunchByIdentifier(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        steam_tool = None
        if programs.IsToolInstalled("Steam"):
            steam_tool = programs.GetToolProgram("Steam")
        if not steam_tool:
            system.LogErrorAndQuit("Steam was not found")

        # Get launch command
        launch_cmd = [
            steam_tool,
            "steam://rungameid/%s" % identifier,
        ]

        # Run launch command
        code = command.RunBlockingCommand(
            cmd = launch_cmd,
            options = command.CommandOptions(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################

    # Download by identifier
    def DownloadByIdentifier(
        self,
        identifier,
        output_dir,
        output_name = None,
        branch = None,
        clean_output = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidIdentifier(identifier):
            return False

        # Get tool
        steamdepot_tool = None
        if programs.IsToolInstalled("SteamDepotDownloader"):
            steamdepot_tool = programs.GetToolProgram("SteamDepotDownloader")
        if not steamdepot_tool:
            system.LogErrorAndQuit("SteamDepotDownloader was not found")

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Make temporary dirs
        tmp_dir_dowload = os.path.join(tmp_dir_result, "download")
        tmp_dir_archive = os.path.join(tmp_dir_result, "archive")
        system.MakeDirectory(
            dir = tmp_dir_download,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        system.MakeDirectory(
            dir = tmp_dir_archive,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Get download command
        download_cmd = [
            steamdepot_tool,
            "-app", identifier,
            "-os", self.GetPlatform(),
            "-osarch", self.GetArchitecture(),
            "-dir", tmp_dir_download
        ]
        if isinstance(branch, str) and len(branch) and branch != "public":
            download_cmd += [
                "-beta", branch
            ]
        if isinstance(self.GetAccountName(), str) and len(self.GetAccountName()):
            download_cmd += [
                "-username", self.GetAccountName(),
                "-remember-password"
            ]

        # Run download command
        command.RunBlockingCommand(
            cmd = download_cmd,
            options = command.CommandOptions(
                blocking_processes = [steamdepot_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
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
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.RemoveDirectory(
                dir = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return False

        # Clean output
        if clean_output:
            system.RemoveDirectoryContents(
                dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Move archived files
        success = system.MoveContents(
            src = tmp_dir_archive,
            dest = output_dir,
            show_progress = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.RemoveDirectory(
                dir = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return False

        # Delete temporary directory
        system.RemoveDirectory(
            dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check result
        return os.path.exists(output_dir)

    ############################################################
