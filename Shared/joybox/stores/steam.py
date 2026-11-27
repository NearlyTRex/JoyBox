# Imports
import types
import importlib

# Local imports
from joybox import config
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import serialization
from joybox import logger
from joybox import fileops
from joybox import network
from joybox import paths
from joybox import settings
from joybox import jsondata
from joybox import webpage
from joybox import storebase
from joybox import strings
from joybox import metadataentry
from joybox import manifest
from joybox import backup
from joybox import steamlookups

# Get vdf, imported on first use
def _get_vdf():
    return importlib.import_module("vdf")

# The Proton wine prefix for an app under a Steam install dir (steamapps/compatdata/<appid>/pfx)
def get_steam_prefix_dir(install_dir, appid):
    return paths.join_paths(install_dir, "steamapps", "compatdata", appid, "pfx")

# The appmanifest_<appid>.acf path Steam writes under steamapps once an app is installed
def get_steam_manifest_file(install_dir, appid):
    return paths.join_paths(install_dir, "steamapps", f"appmanifest_{appid}.acf")

# Index just past the brace closing the VDF block that starts at vdf_start; end of text when unbalanced
def _find_vdf_block_end(info_output, vdf_start):
    brace_count = 0
    for i in range(vdf_start, len(info_output)):
        if info_output[i] == '{':
            brace_count += 1
        if info_output[i] != '}':
            continue
        brace_count -= 1
        if brace_count == 0:
            return i + 1
    return len(info_output)

# Set name, controller support, install dir and the branch's build id and date from app_info_print data
def _set_app_info_values(json_data, appdata, branch):
    appcommon = appdata.get("common", {})
    appconfig = appdata.get("config", {})
    appdepots = appdata.get("depots", {}).get("branches", {}).get(branch, {})
    json_data.set_value(config.JSON_KEY_STORE_NAME, appcommon.get("name", "").strip())
    json_data.set_value(config.JSON_KEY_STORE_CONTROLLER_SUPPORT, appcommon.get("controller_support", "unknown"))
    if appconfig.get("installdir"):
        json_data.set_value(
            config.JSON_KEY_STORE_INSTALLDIR,
            f'STORE_INSTALL_DIR/steamapps/common/{appconfig.get("installdir")}'
        )
    json_data.set_value(config.JSON_KEY_STORE_BUILDID, str(appdepots.get("buildid", config.DEFAULT_BUILDID)))
    json_data.set_value(config.JSON_KEY_STORE_BUILDDATE, str(appdepots.get("timeupdated", "unknown")))

# Steam store
class Steam(storebase.StoreBase):

    TYPE = config.StoreType.STEAM
    PLATFORM = config.Platform.COMPUTER_STEAM
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_STEAM
    KEY = config.JSON_KEY_STEAM
    IDENTIFIER_KEYS = types.MappingProxyType({
        config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_APPID,
    })

    # Constructor
    def __init__(self):
        super().__init__()

        # Get platform / architecture
        self.platform = settings.get_path_value("UserData.Steam", "steam_platform")
        self.arch = settings.get_path_value("UserData.Steam", "steam_arch")
        if not self.platform or not self.arch:
            raise RuntimeError("Ini file does not have a valid platform/arch")

        # Get account name
        self.accountname = settings.get_value("UserData.Steam", "steam_accountname")
        if not self.accountname:
            raise RuntimeError("Ini file does not have a valid account name")

        # Get user details
        self.username = settings.get_value("UserData.Steam", "steam_username")
        self.userid = settings.get_value("UserData.Steam", "steam_userid")
        if not self.username or not self.userid:
            raise RuntimeError("Ini file does not have a valid username")

        # Get web api key
        self.web_api_key = settings.get_value("UserData.Steam", "steam_web_api_key")
        if not self.web_api_key:
            raise RuntimeError("Ini file does not have a valid web api key")

        # Get install dir
        self.install_dir = settings.get_path_value("UserData.Steam", "steam_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # The OS SteamCMD and DepotDownloader fetch builds for, from the settings
    def get_preferred_platform(self):
        return self.platform

    # The CPU architecture DepotDownloader fetches builds for, from the settings
    def get_preferred_architecture(self):
        return self.arch

    # The Steam login account name from the settings, used for SteamCMD and DepotDownloader sign-in
    def get_account_name(self):
        return self.accountname

    # The Steam profile name from the settings; the constructor refuses to build without one
    def get_user_name(self):
        return self.username

    # The configured 64-bit SteamID, or the same account rendered in another SteamIDFormatType
    def get_user_id(self, format_type = None):
        steamid = self.userid
        steamid64ident = 76561197960265728
        steamidacct = int(self.userid) - steamid64ident
        if format_type == config.SteamIDFormatType.STEAMID_3L:
            return "[U:1:" + str(steamidacct) + "]"
        if format_type == config.SteamIDFormatType.STEAMID_3S:
            return str(steamidacct)
        if format_type == config.SteamIDFormatType.STEAMID_CL:
            steamid = "STEAM_0:"
            if steamidacct % 2 == 0:
                steamid += "0:"
            else:
                steamid += "1:"
            steamid += str(steamidacct // 2)
            return steamid
        if format_type == config.SteamIDFormatType.STEAMID_CS:
            return str(steamidacct // 2)
        return steamid

    # The Steam Web API key from the settings, used to list owned games
    def get_web_api_key(self):
        return self.web_api_key

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

    # Get how to sign in again
    def get_login_hint(self):
        return "check steam_userid and steam_web_api_key in the UserData.Steam section of JoyBox.ini"

    # Sign in to SteamCMD interactively with the account name; True at once when already signed in
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Get tool
        steam_tool = programs.find_tool_program("SteamCMD")
        if not steam_tool:
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
            options = commandbase.create_command_options(
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

    # The store page for an appid; None when the page is unreachable
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
        return steamlookups.get_steam_page(identifier)

    ############################################################
    # Purchases
    ############################################################

    # Owned games, free ones included, from a cache under a day old or else the Web API, with userdata save paths
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = self.get_purchases_cache_dir()
        cache_file_purchases = paths.join_paths(cache_dir, "steam_purchases_cache.json")

        # Load from cache if available
        cached_purchases = self._load_cached_purchases(cache_file_purchases, verbose = verbose)
        if cached_purchases is not None:
            return cached_purchases

        # Get steam json
        steam_json = self._fetch_owned_games(verbose = verbose, exit_on_failure = exit_on_failure)
        if not steam_json:
            return None

        # Parse json
        purchases = []
        purchases_data = []
        for entry in steam_json.get("response", {}).get("games", []):
            purchase_data = self._create_owned_game_data(entry)
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.get_platform())
            for key, value in purchase_data.items():
                purchase.set_value(key, value)
            purchases.append(purchase)
            purchases_data.append(purchase_data)

        # Save to cache
        self._save_purchases_cache(cache_dir, cache_file_purchases, purchases_data, verbose = verbose, pretend_run = pretend_run)
        return purchases

    # Cached purchases when the cache is under a day old and holds a list of dicts, else None
    def _load_cached_purchases(self, cache_file_purchases, verbose = False):

        # Check if cache exists and is recent (less than 24 hours old)
        if not paths.does_path_exist(cache_file_purchases):
            return None
        cache_age_hours = paths.get_file_age_in_hours(cache_file_purchases)
        if cache_age_hours >= 24:
            return None
        if verbose:
            logger.log_info("Using cached Steam purchases data (%.1f hours old)" % cache_age_hours)

        # Load from cache
        cached_data = serialization.read_json_file(
            src = cache_file_purchases,
            verbose = verbose,
            exit_on_failure = False)
        if isinstance(cached_data, list) and all(isinstance(entry, dict) for entry in cached_data):
            return [
                jsondata.JsonData(json_data = purchase_data, json_platform = self.get_platform())
                for purchase_data in cached_data
            ]
        if verbose:
            logger.log_warning("Failed to load Steam cache, will fetch fresh data")
        return None

    # The Web API's owned-games json, free games and app info included; None when unreachable or empty
    def _fetch_owned_games(self, verbose = False, exit_on_failure = False):

        # Get steam url
        steam_url = "https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/"
        steam_url += "?steamid=%s" % self.get_user_id(config.SteamIDFormatType.STEAMID_64)
        steam_url += "&include_appinfo=true"
        steam_url += "&include_played_free_games=true"
        steam_url += "&format=json"
        steam_params = {"key": self.get_web_api_key()}
        if not network.is_url_reachable(steam_url, params = steam_params):
            return None

        # Get steam json
        steam_json = network.get_remote_json(
            url = steam_url,
            params = steam_params,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not steam_json:
            logger.log_error("Unable to find steam release information from '%s'" % steam_url)
            return None
        return steam_json

    # Purchase fields for one owned-games entry, on the public branch with its userdata save path
    def _create_owned_game_data(self, entry):
        line_appid = str(entry.get("appid", ""))
        line_title = str(entry.get("name", ""))
        line_url = self.get_latest_url(line_appid)
        return {
            config.JSON_KEY_STORE_APPID: line_appid,
            config.JSON_KEY_STORE_APPURL: line_url,
            config.JSON_KEY_STORE_NAME: line_title.strip(),
            config.JSON_KEY_STORE_BRANCHID: config.SteamBranchType.PUBLIC.lower(),
            config.JSON_KEY_STORE_KEYS: [],
            config.JSON_KEY_STORE_PATHS: [
                paths.join_paths(config.TOKEN_STORE_INSTALL_DIR, "userdata", config.TOKEN_STORE_USER_ID, line_appid)
            ]
        }

    # Write the purchase fields to the cache file, logging the outcome when verbose
    def _save_purchases_cache(self, cache_dir, cache_file_purchases, purchases_data, verbose = False, pretend_run = False):
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

    ############################################################
    # Json
    ############################################################

    # Merge in manifest save paths and registry keys matched by appid, rooted at the game's install dir when known, then the base cleanup
    def augment_jsondata(
        self,
        json_data,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get existing paths and keys
        game_paths = list(json_data.get_value(config.JSON_KEY_STORE_PATHS))
        game_keys = list(json_data.get_value(config.JSON_KEY_STORE_KEYS))

        # Augment by manifest
        manifest_entry = manifest.get_manifest_instance().find_entry_by_steamid(
            steamid = identifier)
        if manifest_entry:
            base_path = None
            if json_data.has_key(config.JSON_KEY_STORE_INSTALLDIR):
                base_path = json_data.get_value(config.JSON_KEY_STORE_INSTALLDIR)
            manifest_paths = manifest_entry.get_paths(base_path)
            game_paths = list(set(game_paths).union(manifest_paths))
            game_keys = list(set(game_keys).union(manifest_entry.get_keys()))

        # Apply base path cleaning logic
        json_data.set_value(config.JSON_KEY_STORE_PATHS, game_paths)
        json_data.set_value(config.JSON_KEY_STORE_KEYS, game_keys)
        return super().augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Name, install dir, controller support and the branch's build id and date from SteamCMD's anonymous app_info_print
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

        # Get app info
        info_output = self._run_app_info_print(identifier, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        if info_output is None:
            return None

        # Get steam json
        steam_json = self._parse_app_info(identifier, info_output)
        if steam_json is None:
            return None

        # Build jsondata
        json_data = self._create_app_jsondata(identifier, branch, steam_json)
        return self.augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Store json for the appid on the branch (public by default) from its parsed app info, before augmenting
    def _create_app_jsondata(self, identifier, branch, steam_json):
        if not isinstance(branch, str) or not branch:
            branch = config.SteamBranchType.PUBLIC.lower()
        json_data = self.create_default_jsondata()
        json_data.set_value(config.JSON_KEY_STORE_APPID, identifier)
        json_data.set_value(config.JSON_KEY_STORE_APPURL, self.get_latest_url(identifier))
        json_data.set_value(config.JSON_KEY_STORE_BRANCHID, branch)
        json_data.set_value(config.JSON_KEY_STORE_PATHS, [
            paths.join_paths(config.TOKEN_STORE_INSTALL_DIR, "userdata", config.TOKEN_STORE_USER_ID, identifier)
        ])
        appdata = steam_json.get(identifier)
        if isinstance(appdata, dict):
            _set_app_info_values(json_data, appdata, branch)
        return json_data

    # SteamCMD's anonymous app_info_print output for the appid; None without SteamCMD or output
    def _run_app_info_print(self, identifier, verbose = False, pretend_run = False, exit_on_failure = False):

        # Get tool
        steamcmd_tool = programs.find_tool_program("SteamCMD")
        if not steamcmd_tool:
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
            options = commandbase.create_command_options(
                blocking_processes = [steamcmd_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0:
            logger.log_error("Unable to find steam information for '%s'" % identifier)
            return None
        return info_output

    # The app's VDF block cut from the app_info_print output and parsed; None, logged, when it cannot be
    def _parse_app_info(self, identifier, info_output):
        vdf = _get_vdf()
        try:
            vdf_start = info_output.find(f'"{identifier}"')
            if vdf_start == -1:
                raise ValueError("App VDF not found in output")
            vdf_end = info_output.find("Unloading Steam API", vdf_start)
            if vdf_end == -1:
                vdf_end = _find_vdf_block_end(info_output, vdf_start)
            vdf_text = info_output[vdf_start:vdf_end].strip()
            return vdf.loads(vdf_text)
        except (SyntaxError, ValueError) as e:
            logger.log_error(e)
            logger.log_error("Unable to parse steam information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None

    ############################################################
    # Metadata
    ############################################################

    # Description and the genre, developer, publisher and release details scraped from the store page, with retries
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

        # Scrape the store page with retries
        return self._scrape_metadata_with_retries(identifier, verbose = verbose, pretend_run = pretend_run)

    # Retry the page scrape in a fresh headless driver, disconnecting it between attempts and at the end
    def _scrape_metadata_with_retries(self, identifier, verbose = False, pretend_run = False):

        # Store web driver for cleanup
        web_driver = None

        # Cleanup function
        def cleanup_driver():
            nonlocal web_driver
            if web_driver:
                self.web_disconnect(
                    web_driver = web_driver,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                web_driver = None

        # Fetch function
        def attempt_metadata_fetch():
            nonlocal web_driver
            web_driver = self._connect_scrape_driver(verbose = verbose, pretend_run = pretend_run)
            if not web_driver:
                return None
            return self._scrape_metadata_page(web_driver, identifier, verbose = verbose)

        # Use retry function with cleanup
        try:
            return webpage.retry_scrape(
                func = attempt_metadata_fetch,
                cleanup_func = cleanup_driver,
                verbose = verbose,
                operation_name = "Steam metadata fetch for '%s'" % identifier)
        finally:

            # Final cleanup
            cleanup_driver()

    # A headless web driver; None in a pretend run that got none, else ScrapeFailed without one
    def _connect_scrape_driver(self, verbose = False, pretend_run = False):
        web_driver = self.web_connect(
            headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not web_driver:
            if pretend_run:
                return None
            raise webpage.ScrapeFailed("Failed to connect to web driver")
        return web_driver

    # Load the store page past its age gate and read the description and details into a metadata entry
    def _scrape_metadata_page(self, web_driver, identifier, verbose = False):

        # Load url
        success = webpage.load_url(web_driver, identifier)
        if not success:
            raise webpage.ScrapeFailed("Failed to load URL: %s" % identifier)

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()

        # Answer the age gate
        steamlookups.answer_steam_age_gate(web_driver, verbose = verbose)

        # Look for game description
        self._read_page_description(web_driver, metadata_entry, verbose = verbose)

        # Look for game details
        element_game_details = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"id": "genresAndManufacturer"}),
            verbose = verbose,
            exit_on_failure = False)
        if element_game_details:

            # Read the details text
            raw_game_details = webpage.get_element_text(element_game_details)
            if raw_game_details:
                steamlookups.read_steam_page_details(raw_game_details, metadata_entry)
        return metadata_entry

    # Set the entry's description from the page's About This Game section, minus its heading
    def _read_page_description(self, web_driver, metadata_entry, verbose = False):
        element_game_description = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"id": "aboutThisGame"}),
            verbose = verbose,
            exit_on_failure = False)
        if element_game_description:
            raw_game_description = webpage.get_element_children_text(element_game_description)
            if raw_game_description:
                description_text = raw_game_description
                description_text = strings.trim_substring_from_start(description_text, "About This Game")
                description_text = strings.trim_substring_from_start(description_text, "About This Software")
                description_text = strings.trim_substring_from_start(description_text, "About This Demo")
                metadata_entry.set_description(description_text)

    ############################################################
    # Assets
    ############################################################

    # The library cover for a box front or the first trailer for a video; None for other types
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
            latest_asset_url = steamlookups.get_steam_cover(identifier)

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = steamlookups.get_steam_trailer(
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

    # Install or validate the app with SteamCMD for the preferred OS; quits when SteamCMD is missing
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
            "+@sSteamCmdForcePlatformType", self.get_preferred_platform(),
            "+login", self.get_account_name(),
            "+app_update", identifier,
            "validate",
            "+quit"
        ]

        # Run install command
        code = command.run_returncode_command(
            cmd = install_cmd,
            options = commandbase.create_command_options(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0

    ############################################################
    # Launch
    ############################################################

    # Start the game through the Steam client's rungameid URL; quits when Steam is missing
    def launch(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_launch_identifier(identifier):
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
            options = commandbase.create_command_options(
                blocking_processes = [steam_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0

    ############################################################
    # Download
    ############################################################

    # Fetch the app (or a beta branch) with DepotDownloader into a temp dir and archive it into output_dir, minus its state folder
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
        steamdepot_tool = self._find_depot_downloader()
        if not steamdepot_tool:
            return False

        # Download into a temporary directory and archive it
        with fileops.temporary_directory(verbose = verbose) as tmp_dir_result:
            if not tmp_dir_result:
                return False

            # Download and archive files
            if not self._fetch_and_archive_depot(
                steamdepot_tool, identifier, branch, tmp_dir_result, output_dir, output_name,
                clean_output = clean_output, show_progress = show_progress, skip_existing = skip_existing, skip_identical = skip_identical,
                verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                return False

        # Check results
        return paths.does_directory_contain_files(output_dir)

    # Fetch the app into download_dir, then archive it into output_dir without DepotDownloader's state folder
    def _fetch_and_archive_depot(
        self, steamdepot_tool, identifier, branch, download_dir, output_dir, output_name,
        clean_output = False, show_progress = False, skip_existing = False, skip_identical = False,
        verbose = False, pretend_run = False, exit_on_failure = False):

        # Run download command
        if not self._run_depot_download(
            steamdepot_tool, identifier, branch, download_dir,
            verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
            return False

        # Archive downloaded files
        return backup.archive_folder(
            input_path = download_dir,
            output_path = output_dir,
            output_name = output_name,
            exclude_paths = [".DepotDownloader"],
            clean_output = clean_output,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # The DepotDownloader program; quits the run when it is not installed
    def _find_depot_downloader(self):
        steamdepot_tool = None
        if programs.is_tool_installed("SteamDepotDownloader"):
            steamdepot_tool = programs.get_tool_program("SteamDepotDownloader")
        if not steamdepot_tool:
            logger.log_error("SteamDepotDownloader was not found", quit_program = True)
        return steamdepot_tool

    # Fetch the app for the preferred OS and arch into download_dir, a non-public branch as a beta; True on exit code 0
    def _run_depot_download(self, steamdepot_tool, identifier, branch, download_dir, verbose = False, pretend_run = False, exit_on_failure = False):

        # Get download command
        download_cmd = [
            steamdepot_tool,
            "-app", identifier,
            "-os", self.get_preferred_platform(),
            "-osarch", self.get_preferred_architecture(),
            "-dir", download_dir
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
            options = commandbase.create_command_options(
                blocking_processes = [steamdepot_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0

    ############################################################
    # Paths
    ############################################################

    # The base token map plus the app's Proton prefix for registry, Public and steamuser profile paths
    def build_path_translation_map(self, appid = None, appname = None):

        # Build translation map
        translation_map = super().build_path_translation_map()
        if appid:
            prefix_path = get_steam_prefix_dir(self.get_install_dir(), appid)
            translation_map[config.TOKEN_USER_REGISTRY_DIR].append(prefix_path)
            translation_map[config.TOKEN_USER_PUBLIC_DIR].append(paths.join_paths(prefix_path, "drive_c", "users", "Public"))
            translation_map[config.TOKEN_USER_PROFILE_DIR].append(paths.join_paths(prefix_path, "drive_c", "users", "steamuser"))
        return translation_map

    # The base variants plus copies of each user-id path in the 64-bit, account-number and legacy SteamID forms
    def add_path_variants(self, path_list = None):

        # Add parent variants
        path_list = super().add_path_variants(path_list)

        # Get user info
        userid_64 = self.get_user_id(config.SteamIDFormatType.STEAMID_64)
        userid_3s = self.get_user_id(config.SteamIDFormatType.STEAMID_3S)
        userid_cs = self.get_user_id(config.SteamIDFormatType.STEAMID_CS)

        # Add user id variants
        for path in list(path_list):
            if config.TOKEN_STORE_USER_ID in path:
                path_list.append(path.replace(config.TOKEN_STORE_USER_ID, userid_64))
                path_list.append(path.replace(config.TOKEN_STORE_USER_ID, userid_3s))
                path_list.append(path.replace(config.TOKEN_STORE_USER_ID, userid_cs))
        return path_list

    ############################################################
