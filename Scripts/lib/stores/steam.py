# Imports
import os, os.path
import sys

# Local imports
import config
import command
import archive
import programs
import serialization
import system
import logger
import environment
import fileops
import network
import paths
import ini
import image
import jsondata
import containers
import datautils
import webpage
import storebase
import strings
import metadataentry
import manifest
import modules

# Get steam page
def get_steam_page(appid):
    url = "https://store.steampowered.com/app/%s" % appid
    if network.is_url_reachable(url):
        return url
    return None

# Get steam cover
def get_steam_cover(appid):
    for cdn_type in config.ContentDeliveryNetworkType.members():
        url = "https://cdn.%s.steamstatic.com/steam/apps/%s/library_600x900_2x.jpg" % (cdn_type.lower(), appid)
        if network.is_url_reachable(url):
            return url
    return None

# Get steam trailer
def get_steam_trailer(
    appid,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for cdn_type in config.ContentDeliveryNetworkType.members():
        asset_url = webpage.get_matching_url(
            url = get_steam_page(appid),
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
def get_steam_prefix_dir(install_dir, appid):
    return paths.join_paths(install_dir, "steamapps", "compatdata", appid, "pfx")

# Get steam manifest file
def get_steam_manifest_file(install_dir, appid):
    return paths.join_paths(install_dir, "steamapps", f"appmanifest_{appid}.acf")

# Find steam appid matches
def find_steam_appid_matches(
    search_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Load appid list
    appid_list = serialization.read_csv_file(
        src = programs.get_tool_path_config_value("SteamAppIDList", "csv"),
        headers = [config.search_result_key_id, config.search_result_key_title],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Build list of matches
    search_results = []
    for entry in appid_list:
        search_result = containers.AssetSearchResult(entry)
        if strings.are_strings_highly_similar(search_name, search_result.get_title()):
            search_result.set_relevance(strings.get_string_similarity_ratio(search_name, search_result.get_title()))
            search_results.append(search_result)
    return search_results

# Find steam appid match
def find_steam_appid_match(
    search_name,
    only_active_pages = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get relevant matches
    search_results = find_steam_appid_matches(
        search_name = search_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if len(search_results) == 0:
        return None

    # Return top search result
    if only_active_pages:
        for search_result in sorted(search_results, key=lambda x: x.get_relevance(), reverse=True):
            steam_page = get_steam_page(search_result.get_id())
            if steam_page:
                return search_result
        return None
    else:
        return search_results[0]

# Find Steam assets
def find_steam_assets(
    search_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get search result
    search_result = find_steam_appid_match(
        search_name = search_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not search_result:
        return []

    # Get asset url
    asset_url = None
    if asset_type == config.AssetType.BOXFRONT:
        asset_url = get_steam_cover(search_result.get_id())
    elif asset_type == config.AssetType.VIDEO:
        asset_url = get_steam_trailer(
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
def find_steam_griddb_covers(
    search_name,
    image_dimensions = None,
    image_types = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get authorization info
    steamgriddb_api_key = ini.get_ini_value("UserData.Scraping", "steamgriddb_api_key")

    # Import steamgrid
    steamgrid = modules.import_python_module_package(
        module_path = programs.get_tool_path_config_value("PySteamGridDB", "package_dir"),
        module_name = programs.get_tool_config_value("PySteamGridDB", "package_name"))

    # Initialize client
    sgdb = steamgrid.SteamGridDB(steamgriddb_api_key)

    # Build search results
    search_results = []
    for game_entry in sgdb.search_game(strings.encode_url_string(search_name, use_plus = True)):
        search_grids = sgdb.get_grids_by_gameid(game_ids=[game_entry.id])
        if datautils.is_iterable_container(search_grids):
            for search_grid in search_grids:

                # Get grid info
                grid_id = game_entry.id
                grid_name = game_entry.name
                grid_release_date = game_entry.release_date
                grid_url = search_grid.url
                grid_width = int(search_grid.width)
                grid_height = int(search_grid.height)

                # Ignore dissimilar images
                if not strings.are_strings_highly_similar(search_name, grid_name):
                    continue

                # Ignore images that do not match requested dimensions
                if datautils.is_iterable_non_string(image_dimensions) and len(image_dimensions) == 2:
                    requested_width, requested_height = map(int, image_dimensions)
                    if grid_width != requested_width or grid_height != requested_height:
                        continue

                # Ignore images that do not match requested types
                if datautils.is_iterable_non_string(image_types) and len(image_types) > 0:
                    found_type = image.get_image_format(grid_url)
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
                search_result.set_relevance(strings.get_string_similarity_ratio(search_name, grid_name))
                search_results.append(search_result)

    # Return search results
    return sorted(search_results, key=lambda x: x.get_relevance(), reverse = True)

# Steam store
class Steam(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get platform / architecture
        self.platform = ini.get_ini_path_value("UserData.Steam", "steam_platform")
        self.arch = ini.get_ini_path_value("UserData.Steam", "steam_arch")
        if not self.platform or not self.arch:
            raise RuntimeError("Ini file does not have a valid platform/arch")

        # Get account name
        self.accountname = ini.get_ini_value("UserData.Steam", "steam_accountname")
        if not self.accountname:
            raise RuntimeError("Ini file does not have a valid account name")

        # Get user details
        self.username = ini.get_ini_value("UserData.Steam", "steam_username")
        self.userid = ini.get_ini_value("UserData.Steam", "steam_userid")
        if not self.username or not self.userid:
            raise RuntimeError("Ini file does not have a valid username")

        # Get web api key
        self.web_api_key = ini.get_ini_value("UserData.Steam", "steam_web_api_key")
        if not self.web_api_key:
            raise RuntimeError("Ini file does not have a valid web api key")

        # Get install dir
        self.install_dir = ini.get_ini_path_value("UserData.Steam", "steam_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def get_name(self):
        return config.StoreType.STEAM.val()

    # Get type
    def get_type(self):
        return config.StoreType.STEAM

    # Get platform
    def get_platform(self):
        return config.Platform.COMPUTER_STEAM

    # Get supercategory
    def get_supercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def get_category(self):
        return config.Category.COMPUTER

    # Get subcategory
    def get_subcategory(self):
        return config.Subcategory.COMPUTER_STEAM

    # Get key
    def get_key(self):
        return config.json_key_steam

    # Get identifier keys
    def get_identifier_keys(self):
        return {
            config.StoreIdentifierType.INFO: config.json_key_store_appid,
            config.StoreIdentifierType.INSTALL: config.json_key_store_appid,
            config.StoreIdentifierType.LAUNCH: config.json_key_store_appid,
            config.StoreIdentifierType.DOWNLOAD: config.json_key_store_appid,
            config.StoreIdentifierType.ASSET: config.json_key_store_appid,
            config.StoreIdentifierType.METADATA: config.json_key_store_appurl,
            config.StoreIdentifierType.PAGE: config.json_key_store_appid
        }

    # Get preferred platform
    def get_preferred_platform(self):
        return self.platform

    # Get preferred architecture
    def get_preferred_architecture(self):
        return self.arch

    # Get account name
    def get_account_name(self):
        return self.accountname

    # Get user name
    def get_user_name(self):
        return self.username

    # Get user id
    def get_user_id(self, format_type = None):
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
    def get_web_api_key(self):
        return self.web_api_key

    # Get install dir
    def get_install_dir(self):
        return self.install_dir

    # Check if store can handle installing
    def can_handle_installing(self):
        return True

    # Check if store can handle launching
    def can_handle_launching(self):
        return True

    # Check if purchases can be imported
    def can_import_purchases(self):
        return True

    # Check if purchases can be downloaded
    def can_download_purchases(self):
        return True

    ############################################################
    # Connection
    ############################################################

    # Login
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Get tool
        steam_tool = None
        if programs.is_tool_installed("SteamCMD"):
            steam_tool = programs.get_tool_program("SteamCMD")
        if not steam_tool:
            logger.log_error("SteamCMD was not found")
            return False

        # Get login command
        login_cmd = [
            steam_tool,
            "+login", self.get_account_name(),
            "+quit"
        ]

        # Run login command
        code = command.run_interactive_command(
            cmd = login_cmd,
            options = command.create_command_options(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Should be successful
        self.set_logged_in(True)
        return True

    ############################################################
    # Page
    ############################################################

    # Get latest url
    def get_latest_url(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_page_identifier(identifier):
            logger.log_warning("Page identifier '%s' was not valid" % identifier)
            return None

        # Return latest url
        return get_steam_page(identifier)

    ############################################################
    # Purchases
    ############################################################

    # Get purchases
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = environment.get_cache_root_dir()
        cache_file_purchases = paths.join_paths(cache_dir, "steam_purchases_cache.json")

        # Check if cache exists and is recent (less than 24 hours old)
        use_cache = False
        if paths.does_path_exist(cache_file_purchases):
            cache_age_hours = paths.get_file_age_in_hours(cache_file_purchases)
            if cache_age_hours < 24:
                use_cache = True
                if verbose:
                    logger.log_info("Using cached Steam purchases data (%.1f hours old)" % cache_age_hours)

        # Load from cache if available
        if use_cache:
            cached_data = serialization.read_json_file(
                src = cache_file_purchases,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if cached_data and isinstance(cached_data, list):
                cached_purchases = []
                for purchase_data in cached_data:
                    purchase = jsondata.JsonData(
                        json_data = purchase_data,
                        json_platform = self.get_platform())
                    cached_purchases.append(purchase)
                return cached_purchases
            else:
                if verbose:
                    logger.log_warning("Failed to load Steam cache, will fetch fresh data")
                use_cache = False

        # Get steam url
        steam_url = "https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/"
        steam_url += "?key=%s" % self.get_web_api_key()
        steam_url += "&steamid=%s" % self.get_user_id(config.SteamIDFormatType.STEAMID_64)
        steam_url += "&include_appinfo=true"
        steam_url += "&include_played_free_games=true"
        steam_url += "&format=json"
        if not network.is_url_reachable(steam_url):
            return None

        # Get steam json
        steam_json = network.get_remote_json(
            url = steam_url,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not steam_json:
            logger.log_error("Unable to find steam release information from '%s'" % steam_url)
            return None

        # Parse json
        purchases = []
        purchases_data = []
        for entry in steam_json.get("response", {}).get("games", []):

            # Gather info
            line_appid = str(entry.get("appid", ""))
            line_title = str(entry.get("name", ""))
            line_keys = []
            line_paths = [
                paths.join_paths(config.token_store_install_dir, "userdata", config.token_store_user_id, line_appid)
            ]

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.get_platform())
            purchase.set_value(config.json_key_store_appid, line_appid)
            purchase.set_value(config.json_key_store_appurl, self.get_latest_url(line_appid))
            purchase.set_value(config.json_key_store_name, line_title.strip())
            purchase.set_value(config.json_key_store_branchid, config.SteamBranchType.PUBLIC.lower())
            purchase.set_value(config.json_key_store_keys, line_keys)
            purchase.set_value(config.json_key_store_paths, line_paths)
            purchases.append(purchase)

            # Store data for caching
            purchases_data.append({
                config.json_key_store_appid: line_appid,
                config.json_key_store_appurl: self.get_latest_url(line_appid),
                config.json_key_store_name: line_title.strip(),
                config.json_key_store_branchid: config.SteamBranchType.PUBLIC.lower(),
                config.json_key_store_keys: line_keys,
                config.json_key_store_paths: line_paths
            })

        # Save to cache
        fileops.make_directory(cache_dir, verbose = verbose, pretend_run = pretend_run)
        success = serialization.write_json_file(
            src = cache_file_purchases,
            json_data = purchases_data,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if success and verbose:
            logger.log_info("Saved Steam purchases data to cache")
        elif not success and verbose:
            logger.log_warning("Failed to save Steam cache")
        return purchases

    ############################################################
    # Json
    ############################################################

    # Augment jsondata
    def augment_jsondata(
        self,
        json_data,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get existing paths and keys
        game_paths = list(json_data.get_value(config.json_key_store_paths))
        game_keys = list(json_data.get_value(config.json_key_store_keys))

        # Augment by manifest
        manifest_entry = manifest.get_manifest_instance().find_entry_by_steamid(
            steamid = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if manifest_entry:
            base_path = None
            if json_data.has_key(config.json_key_store_installdir):
                base_path = paths.join_paths(
                    config.token_store_install_dir,
                    "steamapps",
                    "common",
                    json_data.get_value(config.json_key_store_installdir))
            manifest_paths = manifest_entry.get_paths(base_path)
            game_paths = list(set(game_paths).union(manifest_paths))
            game_keys = list(set(game_keys).union(manifest_entry.get_keys()))

        # Apply base path cleaning logic
        json_data.set_value(config.json_key_store_paths, game_paths)
        json_data.set_value(config.json_key_store_keys, game_keys)
        return super().AugmentJsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get latest jsondata
    def get_latest_jsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_info_identifier(identifier):
            logger.log_warning("Info identifier '%s' was not valid" % identifier)
            return None

        # Get tool
        steamcmd_tool = None
        if programs.is_tool_installed("SteamCMD"):
            steamcmd_tool = programs.get_tool_program("SteamCMD")
        if not steamcmd_tool:
            logger.log_error("SteamCMD was not found")
            return None

        # Get info command
        info_cmd = [
            steamcmd_tool,
            "+login", "anonymous",
            "+app_info_print", identifier,
            "+quit"
        ]

        # Run info command
        info_output = command.run_output_command(
            cmd = info_cmd,
            options = command.create_command_options(
                blocking_processes = [steamcmd_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0:
            logger.log_error("Unable to find steam information for '%s'" % identifier)
            return None

        # Get steam json
        steam_json = {}
        try:
            import vdf
            vdf_start = info_output.find(f'"{identifier}"')
            if vdf_start == -1:
                raise ValueError("App VDF not found in output")
            vdf_end = info_output.find("Unloading Steam API", vdf_start)
            if vdf_end == -1:
                brace_count = 0
                vdf_end = len(info_output)
                for i in range(vdf_start, len(info_output)):
                    if info_output[i] == '{':
                        brace_count += 1
                    elif info_output[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            vdf_end = i + 1
                            break
            vdf_text = info_output[vdf_start:vdf_end].strip()
            steam_json = vdf.loads(vdf_text)
        except Exception as e:
            logger.log_error(e)
            logger.log_error("Unable to parse steam information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.json_key_store_appid, identifier)
        json_data.set_value(config.json_key_store_appurl, self.get_latest_url(identifier))
        if isinstance(branch, str) and len(branch):
            json_data.set_value(config.json_key_store_branchid, branch)
        else:
            json_data.set_value(config.json_key_store_branchid, "public")
        json_data.set_value(config.json_key_store_paths, [
            paths.join_paths(config.token_store_install_dir, "userdata", config.token_store_user_id, identifier)
        ])
        if identifier in steam_json:
            appdata = steam_json.get(identifier, {})
            appcommon = appdata.get("common", {})
            appconfig = appdata.get("config", {})
            appdepots = appdata.get("depots", {}).get("branches", {}).get(branch, {})
            json_data.set_value(config.json_key_store_name, appcommon.get("name", "").strip())
            json_data.set_value(config.json_key_store_controller_support, appcommon.get("controller_support", "unknown"))
            if appconfig.get("installdir"):
                json_data.set_value(
                    config.json_key_store_installdir,
                    f'STORE_INSTALL_DIR/steamapps/common/{appconfig.get("installdir")}'
                )
            json_data.set_value(config.json_key_store_buildid, str(appdepots.get("buildid", config.default_buildid)))
            json_data.set_value(config.json_key_store_builddate, str(appdepots.get("timeupdated", "unknown")))
        return self.augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Metadata
    ############################################################

    # Get latest metadata
    def get_latest_metadata(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_metadata_identifier(identifier):
            logger.log_warning("Metadata identifier '%s' was not valid" % identifier)
            return None

        # Store web driver for cleanup
        web_driver = None

        # Cleanup function
        def cleanup_driver():
            if web_driver:
                self.web_disconnect(
                    web_driver = web_driver,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)

        # Fetch function
        def attempt_metadata_fetch():
            nonlocal web_driver

            # Connect to web
            web_driver = self.web_connect(
                headless = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not web_driver:
                raise Exception("Failed to connect to web driver")

            # Load url
            success = webpage.load_url(web_driver, identifier)
            if not success:
                raise Exception("Failed to load URL: %s" % identifier)

            # Create metadata entry
            metadata_entry = metadataentry.MetadataEntry()

            # Check for age gate (don't exit on failure to find the age gate)
            element_age_gate = webpage.wait_for_element(
                driver = web_driver,
                locator = webpage.ElementLocator({"id": "app_agegate"}),
                wait_time = 5,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if element_age_gate:

                # Get age selectors
                day_selector = webpage.get_element(
                    parent = element_age_gate,
                    locator = webpage.ElementLocator({"id": "ageDay"}),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                month_selector = webpage.get_element(
                    parent = element_age_gate,
                    locator = webpage.ElementLocator({"id": "ageMonth"}),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                year_selector = webpage.get_element(
                    parent = element_age_gate,
                    locator = webpage.ElementLocator({"id": "ageYear"}),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)

                # Select date
                if day_selector and month_selector and year_selector:
                    webpage.send_keys_to_element(day_selector, "1")
                    webpage.send_keys_to_element(month_selector, "January")
                    webpage.send_keys_to_element(year_selector, "1980")

                    # Click confirm button
                    confirm_button = webpage.get_element(
                        parent = element_age_gate,
                        locator = webpage.ElementLocator({"id": "view_product_page_btn"}),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = False)
                    if confirm_button:
                        webpage.click_element(confirm_button)

            # Look for game description
            element_game_description = webpage.wait_for_element(
                driver = web_driver,
                locator = webpage.ElementLocator({"id": "aboutThisGame"}),
                wait_time = 15,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if element_game_description:
                raw_game_description = webpage.get_element_children_text(element_game_description)
                if raw_game_description:
                    description_text = raw_game_description
                    description_text = strings.trim_substring_from_start(description_text, "About This Game")
                    description_text = strings.trim_substring_from_start(description_text, "About This Software")
                    description_text = strings.trim_substring_from_start(description_text, "About This Demo")
                    metadata_entry.set_description(description_text)

            # Look for game details
            element_game_details = webpage.get_element(
                parent = web_driver,
                locator = webpage.ElementLocator({"id": "genresAndManufacturer"}),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if element_game_details:

                # Grab the information text
                raw_game_details = webpage.get_element_text(element_game_details)
                if raw_game_details:
                    for game_detail_line in raw_game_details.split("\n"):

                        # Release
                        if strings.does_string_start_with_substring(game_detail_line, "Release Date:"):
                            release_text = strings.trim_substring_from_start(game_detail_line, "Release Date:").strip()
                            release_text = strings.convert_date_string(release_text, "%b %d, %Y", "%Y-%m-%d")
                            metadata_entry.set_release(release_text)

                        # Developer
                        elif strings.does_string_start_with_substring(game_detail_line, "Developer:"):
                            developer_text = strings.trim_substring_from_start(game_detail_line, "Developer:").strip()
                            metadata_entry.set_developer(developer_text)

                        # Publisher
                        elif strings.does_string_start_with_substring(game_detail_line, "Publisher:"):
                            publisher_text = strings.trim_substring_from_start(game_detail_line, "Publisher:").strip()
                            metadata_entry.set_publisher(publisher_text)

                        # Genre
                        elif strings.does_string_start_with_substring(game_detail_line, "Genre:"):
                            genre_text = strings.trim_substring_from_start(game_detail_line, "Genre:").strip().replace(", ", ";")
                            metadata_entry.set_genre(genre_text)
            return metadata_entry

        # Use retry function with cleanup
        result = datautils.retry_with_backoff(
            func = attempt_metadata_fetch,
            cleanup_func = cleanup_driver,
            max_retries = 3,
            initial_delay = 2,
            backoff_factor = 2,
            verbose = verbose,
            operation_name = "Steam metadata fetch for '%s'" % identifier)

        # Final cleanup
        cleanup_driver()
        return result

    ############################################################
    # Assets
    ############################################################

    # Get latest asset url
    def get_latest_asset_url(
        self,
        identifier,
        asset_type,
        game_name = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_asset_identifier(identifier):
            logger.log_warning("Asset identifier '%s' was not valid" % identifier)
            return None

        # Latest asset url
        latest_asset_url = None

        # BoxFront
        if asset_type == config.AssetType.BOXFRONT:
            latest_asset_url = get_steam_cover(identifier)

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = get_steam_trailer(
                appid = identifier,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Return latest asset url
        return latest_asset_url

    ############################################################
    # Install
    ############################################################

    # Check if installed
    def is_installed(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_install_identifier(identifier):
            logger.log_warning("Install identifier '%s' was not valid" % identifier)
            return False

        # Check for manifest
        return paths.is_path_file(get_steam_manifest_file(self.get_install_dir(), identifier))

    # Install
    def install(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_install_identifier(identifier):
            logger.log_warning("Install identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        steam_tool = None
        if programs.is_tool_installed("SteamCMD"):
            steam_tool = programs.get_tool_program("SteamCMD")
        if not steam_tool:
            logger.log_error("SteamCMD was not found", quit_program = True)
            return False

        # Get install command
        install_cmd = [
            steam_tool,
            "@sSteamCmdForcePlatformType", self.get_preferred_platform(),
            "+login", self.get_account_name(),
            "app_update", identifier,
            "validate",
            "+quit"
        ]

        # Run install command
        code = command.run_returncode_command(
            cmd = install_cmd,
            options = command.create_command_options(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################
    # Launch
    ############################################################

    # Launch
    def launch(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_install_identifier(identifier):
            logger.log_warning("Launch identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        steam_tool = None
        if programs.is_tool_installed("Steam"):
            steam_tool = programs.get_tool_program("Steam")
        if not steam_tool:
            logger.log_error("Steam was not found", quit_program = True)
            return False

        # Get launch command
        launch_cmd = [
            steam_tool,
            "steam://rungameid/%s" % identifier,
        ]

        # Run launch command
        code = command.run_returncode_command(
            cmd = launch_cmd,
            options = command.create_command_options(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################
    # Download
    ############################################################

    # Download
    def download(
        self,
        identifier,
        output_dir,
        output_name = None,
        branch = None,
        clean_output = False,
        show_progress = False,
        skip_existing = False,
        skip_identical = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_download_identifier(identifier):
            logger.log_warning("Download identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        steamdepot_tool = None
        if programs.is_tool_installed("SteamDepotDownloader"):
            steamdepot_tool = programs.get_tool_program("SteamDepotDownloader")
        if not steamdepot_tool:
            logger.log_error("SteamDepotDownloader was not found", quit_program = True)
            return False

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Get download command
        download_cmd = [
            steamdepot_tool,
            "-app", identifier,
            "-os", self.get_preferred_platform(),
            "-osarch", self.get_architecture(),
            "-dir", tmp_dir_result
        ]
        if isinstance(branch, str) and len(branch) and branch != "public":
            download_cmd += [
                "-beta", branch
            ]
        if isinstance(self.get_account_name(), str) and len(self.get_account_name()):
            download_cmd += [
                "-username", self.get_account_name(),
                "-remember-password"
            ]

        # Run download command
        code = command.run_returncode_command(
            cmd = download_cmd,
            options = command.create_command_options(
                blocking_processes = [steamdepot_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Archive downloaded files
        success = backup.archive_folder(
            input_path = tmp_dir_result,
            output_path = output_dir,
            output_name = output_name,
            excludes = [".DepotDownloader"],
            clean_output = clean_output,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Delete temporary directory
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check results
        return paths.does_directory_contain_files(output_dir)

    ############################################################
    # Paths
    ############################################################

    # Build path translation map
    def build_path_translation_map(self, appid = None, appname = None):

        # Build translation map
        translation_map = super().BuildPathTranslationMap()
        if appid:
            prefix_path = get_steam_prefix_dir(self.get_install_dir(), appid)
            translation_map[config.token_user_registry_dir].append(prefix_path)
            translation_map[config.token_user_public_dir].append(paths.join_paths(prefix_path, "drive_c", "users", "Public"))
            translation_map[config.token_user_profile_dir].append(paths.join_paths(prefix_path, "drive_c", "users", "steamuser"))
        return translation_map

    # Get registered paths
    def add_path_variants(self, paths = []):

        # Add parent variants
        paths = super().AddPathVariants(paths)

        # Get user info
        userid_64 = self.get_user_id(config.SteamIDFormatType.STEAMID_64)
        userid_3s = self.get_user_id(config.SteamIDFormatType.STEAMID_3S)
        userid_cs = self.get_user_id(config.SteamIDFormatType.STEAMID_CS)

        # Add user id variants
        for path in paths:
            if config.token_store_user_id in path:
                paths.append(path.replace(config.token_store_user_id, userid_64))
                paths.append(path.replace(config.token_store_user_id, userid_3s))
                paths.append(path.replace(config.token_store_user_id, userid_cs))
        return paths

    ############################################################
