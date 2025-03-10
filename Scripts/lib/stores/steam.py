# Imports
import os, os.path
import sys

# Local imports
import config
import command
import archive
import programs
import system
import environment
import network
import ini
import image
import jsondata
import containers
import webpage
import storebase
import metadataentry

# Get steam page
def GetSteamPage(appid):
    url = "https://store.steampowered.com/app/%s" % appid
    if network.IsUrlReachable(url):
        return url
    return None

# Get steam cover
def GetSteamCover(appid):
    for cdn_type in config.ContentDeliveryNetworkType.members():
        url = "https://cdn.%s.steamstatic.com/steam/apps/%s/library_600x900_2x.jpg" % (cdn_type.lower(), appid)
        if network.IsUrlReachable(url):
            return url
    return None

# Get steam trailer
def GetSteamTrailer(
    appid,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for cdn_type in config.ContentDeliveryNetworkType.members():
        asset_url = webpage.GetMatchingUrl(
            url = GetSteamPage(appid),
            base_url = "https://video.%s.steamstatic.com/store_trailers" % cdn_type.lower(),
            starts_with = "https://video.%s.steamstatic.com/store_trailers" % cdn_type.lower(),
            ends_with = ".mp4",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if asset_url:
            return asset_url
    return None

# Get steam prefix dir
def GetSteamPrefixDir(install_dir, appid):
    return system.JoinPaths(install_dir, "steamapps", "compatdata", appid, "pfx")

# Find steam appid matches
def FindSteamAppIDMatches(
    search_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Load appid list
    appid_list = system.ReadCsvFile(
        src = programs.GetToolPathConfigValue("SteamAppIDList", "csv"),
        headers = [config.search_result_key_id, config.search_result_key_title],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Build list of matches
    search_results = []
    for entry in appid_list:
        search_result = containers.AssetSearchResult(entry)
        if system.AreStringsHighlySimilar(search_name, search_result.get_title()):
            search_result.set_relevance(system.GetStringSimilarityRatio(search_name, search_result.get_title()))
            search_results.append(search_result)
    return search_results

# Find steam appid match
def FindSteamAppIDMatch(
    search_name,
    only_active_pages = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get relevant matches
    search_results = FindSteamAppIDMatches(
        search_name = search_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if len(search_results) == 0:
        return None

    # Return top search result
    if only_active_pages:
        for search_result in sorted(search_results, key=lambda x: x.get_relevance(), reverse=True):
            steam_page = GetSteamPage(search_result.get_id())
            if steam_page:
                return search_result
        return None
    else:
        return search_results[0]

# Find Steam assets
def FindSteamAssets(
    search_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get search result
    search_result = FindSteamAppIDMatch(
        search_name = search_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not search_result:
        return []

    # Get asset url
    asset_url = None
    if asset_type == config.AssetType.BOXFRONT:
        asset_url = GetSteamCover(search_result.get_id())
    elif asset_type == config.AssetType.VIDEO:
        asset_url = GetSteamTrailer(
            appid = search_result.get_id(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not asset_url:
        return []

    # Return search result
    search_result.set_url(asset_url)
    return [search_result]

# Find SteamGridDB covers
def FindSteamGridDBCovers(
    search_name,
    image_dimensions = None,
    image_types = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get authorization info
    steamgriddb_api_key = ini.GetIniValue("UserData.Scraping", "steamgriddb_api_key")

    # Import steamgrid
    steamgrid = environment.ImportPythonModulePackage(
        module_path = programs.GetToolPathConfigValue("PySteamGridDB", "package_dir"),
        module_name = programs.GetToolConfigValue("PySteamGridDB", "package_name"))

    # Initialize client
    sgdb = steamgrid.SteamGridDB(steamgriddb_api_key)

    # Build search results
    search_results = []
    for game_entry in sgdb.search_game(system.EncodeUrlString(search_name, use_plus = True)):
        search_grids = sgdb.get_grids_by_gameid(game_ids=[game_entry.id])
        if system.IsIterableContainer(search_grids):
            for search_grid in search_grids:

                # Get grid info
                grid_id = game_entry.id
                grid_name = game_entry.name
                grid_release_date = game_entry.release_date
                grid_url = search_grid.url
                grid_width = int(search_grid.width)
                grid_height = int(search_grid.height)

                # Ignore dissimilar images
                if not system.AreStringsHighlySimilar(search_name, grid_name):
                    continue

                # Ignore images that do not match requested dimensions
                if system.IsIterableNonString(image_dimensions) and len(image_dimensions) == 2:
                    requested_width, requested_height = map(int, image_dimensions)
                    if grid_width != requested_width or grid_height != requested_height:
                        continue

                # Ignore images that do not match requested types
                if system.IsIterableNonString(image_types) and len(image_types) > 0:
                    found_type = image.GetImageFormat(grid_url)
                    if found_type and found_type not in image_types:
                        continue

                # Add search result
                search_result = containers.AssetSearchResult()
                search_result.set_id(grid_id)
                search_result.set_title(grid_name)
                search_result.set_description(f"{grid_name} ({grid_release_date})")
                search_result.set_date(grid_release_date)
                search_result.set_url(grid_url)
                search_result.set_width(grid_width)
                search_result.set_height(grid_height)
                search_result.set_relevance(system.GetStringSimilarityRatio(search_name, grid_name))
                search_results.append(search_result)

    # Return search results
    return sorted(search_results, key=lambda x: x.get_relevance(), reverse = True)

# Steam store
class Steam(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get platform / architecture
        self.platform = ini.GetIniPathValue("UserData.Steam", "steam_platform")
        self.arch = ini.GetIniPathValue("UserData.Steam", "steam_arch")
        if not self.platform or not self.arch:
            raise RuntimeError("Ini file does not have a valid platform/arch")

        # Get account name
        self.accountname = ini.GetIniValue("UserData.Steam", "steam_accountname")
        if not self.accountname:
            raise RuntimeError("Ini file does not have a valid account name")

        # Get user details
        self.username = ini.GetIniValue("UserData.Steam", "steam_username")
        self.userid = ini.GetIniValue("UserData.Steam", "steam_userid")
        if not self.username or not self.userid:
            raise RuntimeError("Ini file does not have a valid username")

        # Get web api key
        self.web_api_key = ini.GetIniValue("UserData.Steam", "steam_web_api_key")
        if not self.web_api_key:
            raise RuntimeError("Ini file does not have a valid web api key")

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Steam", "steam_install_dir")
        if not system.IsPathValid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.STEAM.val()

    # Get type
    def GetType(self):
        return config.StoreType.STEAM

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_STEAM

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_STEAM

    # Get key
    def GetKey(self):
        return config.json_key_steam

    # Get preferred platform
    def GetPreferredPlatform(self):
        return self.platform

    # Get preferred architecture
    def GetPreferredArchitecture(self):
        return self.arch

    # Get account name
    def GetAccountName(self):
        return self.accountname

    # Get user name
    def GetUserName(self):
        return self.username

    # Get user id
    def GetUserId(self, format_type = None):
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

    # Check if purchases can be imported
    def CanImportPurchases(self):
        return True

    ############################################################
    # Identifiers
    ############################################################

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.StoreIdentifierType.METADATA:
            return json_wrapper.get_value(config.json_key_store_appurl)
        return json_wrapper.get_value(config.json_key_store_appid)

    ############################################################
    # Connection
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
            system.LogError("SteamCMD was not found", quit_program = True)

        # Get login command
        login_cmd = [
            steam_tool,
            "+login", self.GetAccountName(),
            "+quit"
        ]

        # Run login command
        code = command.RunBlockingCommand(
            cmd = login_cmd,
            options = command.CreateCommandOptions(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################
    # Page
    ############################################################

    # Get latest url
    def GetLatestUrl(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidPageIdentifier(identifier):
            system.LogWarning("Page identifier '%s' was not valid" % identifier)
            return None

        # Return latest url
        return GetSteamPage(identifier)

    ############################################################
    # Purchases
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
                        system.JoinPaths(config.token_store_install_dir, "userdata", config.token_store_user_id, line_appid)
                    ]

                    # Create purchase
                    purchase = jsondata.JsonData(
                        json_data = {},
                        json_platform = self.GetPlatform())
                    purchase.set_value(config.json_key_store_appid, line_appid)
                    purchase.set_value(config.json_key_store_appurl, self.GetLatestUrl(line_appid))
                    purchase.set_value(config.json_key_store_name, line_title.strip())
                    purchase.set_value(config.json_key_store_branchid, config.SteamBranchType.PUBLIC.lower())
                    purchase.set_value(config.json_key_store_keys, line_keys)
                    purchase.set_value(config.json_key_store_paths, line_paths)
                    purchases.append(purchase)
        return purchases

    ############################################################
    # Json
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
        if not self.IsValidInfoIdentifier(identifier):
            system.LogWarning("Info identifier '%s' was not valid" % identifier)
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
            options = command.CreateCommandOptions(
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
            system.JoinPaths(config.token_store_install_dir, "userdata", config.token_store_user_id, identifier)
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
                    game_info[config.json_key_store_installdir] = "STORE_INSTALL_DIR/steamapps/common/%s" % str(appconfig["installdir"])
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
            manifest_entry = self.manifest.find_entry_by_steamid(
                steamid = identifier,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if manifest_entry:

                # Get existing paths and keys
                game_paths = set(game_info[config.json_key_store_paths])
                game_keys = set(game_info[config.json_key_store_keys])

                # Get base path
                base_path = None
                if config.json_key_store_installdir in game_info:
                    base_path = system.JoinPaths(
                        config.token_store_install_dir,
                        "steamapps",
                        "common",
                        game_info[config.json_key_store_installdir])

                # Update paths and keys
                game_paths = game_paths.union(manifest_entry.get_paths(base_path))
                game_keys = game_keys.union(manifest_entry.get_keys())

                # Save paths and keys
                game_info[config.json_key_store_paths] = system.SortStrings(game_paths)
                game_info[config.json_key_store_keys] = system.SortStrings(game_keys)

        # Return game info
        return jsondata.JsonData(game_info, self.GetPlatform())

    ############################################################
    # Metadata
    ############################################################

    # Get latest metadata
    def GetLatestMetadata(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidMetadataIdentifier(identifier):
            system.LogWarning("Metadata identifier '%s' was not valid" % identifier)
            return None

        # Connect to web
        web_driver = self.WebConnect(
            headless = True,
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

        # Check for age gate
        # Do not exit on failure to find the age gate
        element_age_gate = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"id": "app_agegate"}),
            wait_time = 5,
            verbose = verbose,
            pretend_run = pretend_run)
        if element_age_gate:

            # Get age selectors
            day_selector = webpage.GetElement(parent = element_age_gate, locator = webpage.ElementLocator({"id": "ageDay"}))
            month_selector = webpage.GetElement(parent = element_age_gate, locator = webpage.ElementLocator({"id": "ageMonth"}))
            year_selector = webpage.GetElement(parent = element_age_gate, locator = webpage.ElementLocator({"id": "ageYear"}))

            # Select date
            webpage.SendKeysToElement(day_selector, "1")
            webpage.SendKeysToElement(month_selector, "January")
            webpage.SendKeysToElement(year_selector, "1980")

            # Click confirm button
            confirm_button = webpage.GetElement(
                parent = element_age_gate,
                locator = webpage.ElementLocator({"id": "view_product_page_btn"}))
            webpage.ClickElement(confirm_button)

        # Look for game description
        element_game_description = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"id": "aboutThisGame"}),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
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
    # Assets
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
        if not self.IsValidAssetIdentifier(identifier):
            system.LogWarning("Asset identifier '%s' was not valid" % identifier)
            return None

        # Latest asset url
        latest_asset_url = None

        # BoxFront
        if asset_type == config.AssetType.BOXFRONT:
            latest_asset_url = GetSteamCover(identifier)

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = GetSteamTrailer(
                appid = identifier,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Return latest asset url
        return latest_asset_url

    ############################################################
    # Install
    ############################################################

    # Install by identifier
    def InstallByIdentifier(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidInstallIdentifier(identifier):
            system.LogWarning("Install identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        steam_tool = None
        if programs.IsToolInstalled("SteamCMD"):
            steam_tool = programs.GetToolProgram("SteamCMD")
        if not steam_tool:
            system.LogError("SteamCMD was not found", quit_program = True)

        # Get install command
        install_cmd = [
            steam_tool,
            "@sSteamCmdForcePlatformType", self.GetPreferredPlatform(),
            "+login", self.GetAccountName(),
            "app_update", identifier,
            "validate",
            "+quit"
        ]

        # Run install command
        code = command.RunBlockingCommand(
            cmd = install_cmd,
            options = command.CreateCommandOptions(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################
    # Launch
    ############################################################

    # Launch by identifier
    def LaunchByIdentifier(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidInstallIdentifier(identifier):
            system.LogWarning("Launch identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        steam_tool = None
        if programs.IsToolInstalled("Steam"):
            steam_tool = programs.GetToolProgram("Steam")
        if not steam_tool:
            system.LogError("Steam was not found", quit_program = True)

        # Get launch command
        launch_cmd = [
            steam_tool,
            "steam://rungameid/%s" % identifier,
        ]

        # Run launch command
        code = command.RunBlockingCommand(
            cmd = launch_cmd,
            options = command.CreateCommandOptions(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################
    # Download
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
        if not self.IsValidDownloadIdentifier(identifier):
            system.LogWarning("Download identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        steamdepot_tool = None
        if programs.IsToolInstalled("SteamDepotDownloader"):
            steamdepot_tool = programs.GetToolProgram("SteamDepotDownloader")
        if not steamdepot_tool:
            system.LogError("SteamDepotDownloader was not found", quit_program = True)

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Get download command
        download_cmd = [
            steamdepot_tool,
            "-app", identifier,
            "-os", self.GetPreferredPlatform(),
            "-osarch", self.GetArchitecture(),
            "-dir", tmp_dir_result
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
        code = command.RunBlockingCommand(
            cmd = download_cmd,
            options = command.CreateCommandOptions(
                blocking_processes = [steamdepot_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Archive downloaded files
        success = self.Archive(
            source_dir = tmp_dir_result,
            output_dir = output_dir,
            output_name = output_name,
            excludes = [".DepotDownloader"],
            clean_output = clean_output,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Delete temporary directory
        system.RemoveDirectory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check results
        return system.DoesDirectoryContainFiles(output_dir)

    ############################################################
    # Paths
    ############################################################

    # Build path translation map
    def BuildPathTranslationMap(self, appid = None, appname = None):

        # Build translation map
        translation_map = super().BuildPathTranslationMap()
        if appid:
            prefix_path = GetSteamPrefixDir(self.GetInstallDir(), appid)
            translation_map[config.token_user_registry_dir].append(prefix_path)
            translation_map[config.token_user_public_dir].append(system.JoinPaths(prefix_path, "drive_c", "users", "Public"))
            translation_map[config.token_user_profile_dir].append(system.JoinPaths(prefix_path, "drive_c", "users", "steamuser"))
        return translation_map

    # Get registered paths
    def AddPathVariants(self, paths = []):

        # Add parent variants
        paths = super().AddPathVariants(paths)

        # Get user info
        userid_64 = self.GetUserId(config.SteamIDFormatType.STEAMID_64)
        userid_3s = self.GetUserId(config.SteamIDFormatType.STEAMID_3S)
        userid_cs = self.GetUserId(config.SteamIDFormatType.STEAMID_CS)

        # Add user id variants
        for path in paths:
            if config.token_store_user_id in path:
                paths.append(path.replace(config.token_store_user_id, userid_64))
                paths.append(path.replace(config.token_store_user_id, userid_3s))
                paths.append(path.replace(config.token_store_user_id, userid_cs))
        return paths

    ############################################################
