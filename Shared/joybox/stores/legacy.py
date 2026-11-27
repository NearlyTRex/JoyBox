# Imports
import types

# Local imports
from joybox import config
from joybox import command
from joybox import programs
from joybox import logger
from joybox import serialization
from joybox import settings
from joybox import jsondata
from joybox import webpage
from joybox import webfetch
from joybox import storebase
from joybox import strings
from joybox import metadataassetcollector
from joybox import paths

# Get stripped string value from heirloom json, empty when missing or not a string
def get_json_string(json_object, key):
    value = json_object.get(key)
    if not isinstance(value, str):
        return ""
    return value.strip()

# Legacy store
class Legacy(storebase.StoreBase):

    TYPE = config.StoreType.LEGACY
    PLATFORM = config.Platform.COMPUTER_LEGACY_GAMES
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_LEGACY_GAMES
    KEY = config.JSON_KEY_LEGACY
    IDENTIFIER_KEYS = types.MappingProxyType({
        config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_NAME,
    })

    # Constructor
    def __init__(self):
        super().__init__()

        # Get user details
        self.username = settings.get_value("UserData.Legacy", "legacy_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get install dir
        self.install_dir = settings.get_path_value("UserData.Legacy", "legacy_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # The Legacy Games username from the settings; the constructor refuses to build without one
    def get_user_name(self):
        return self.username

    # Check if purchases can be imported
    def can_import_purchases(self):
        return True

    # Check if purchases can be downloaded
    def can_download_purchases(self):
        return True

    ############################################################
    # Connection
    ############################################################

    # Sign in through Heirloom interactively, then refresh it; True at once when already signed in
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Get script command
        script_cmd = programs.get_python_script_command("Heirloom")
        if not script_cmd:
            return False

        # Get login command
        login_cmd = script_cmd + [
                        "login"
        ]

        # Run login command
        code = command.run_interactive_command(
            cmd = login_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Get refresh command
        refresh_cmd = script_cmd + [
                        "refresh"
        ]

        # Run refresh command
        code = command.run_interactive_command(
            cmd = refresh_cmd,
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

    # Big Fish Games page of the closest title found by searching its site in a headless browser, query stripped; None when none is close
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

        # Search function
        def attempt_url_search():
            nonlocal web_driver

            # Connect to web
            web_driver = self.web_connect(
                headless = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not web_driver:
                if pretend_run:
                    return None
                raise webpage.ScrapeFailed("Failed to connect to web driver")

            # Get search terms
            search_terms = strings.encode_url_string(identifier.strip(), use_plus = True)

            # Load url
            success = webpage.load_url(web_driver, "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=" + search_terms)
            if not success:
                raise webpage.ScrapeFailed("Failed to load search URL")

            # Find the root container element
            element_search_result = webpage.wait_for_element(
                driver = web_driver,
                locator = webpage.ElementLocator({"class": "productcollection__root"}),
                verbose = verbose,
                exit_on_failure = False)
            if not element_search_result:
                return None  # No search results found, not an error

            # Score each potential title compared to the original title
            scores_list = []
            game_cells = webpage.get_element(
                parent = element_search_result,
                locator = webpage.ElementLocator({"class": "productcollection__items"}),
                all_elements = True,
                verbose = verbose,
                exit_on_failure = False)
            if game_cells:
                for game_cell in game_cells:
                    game_title_element = webpage.get_element(
                        parent = game_cell,
                        locator = webpage.ElementLocator({"class": "productcollection__item-title"}),
                        verbose = verbose,
                        exit_on_failure = False)
                    if game_title_element:
                        game_cell_text = webpage.get_element_children_text(game_title_element)
                        if game_cell_text:
                            # Add comparison score
                            score_entry = {}
                            score_entry["element"] = game_cell
                            score_entry["ratio"] = strings.get_string_similarity_ratio(identifier, game_cell_text)
                            scores_list.append(score_entry)

            # Get the best url match among results close enough to the name
            appurl = None
            min_match_score = webpage.get_min_match_score()
            for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
                if score_entry["ratio"] < min_match_score:
                    break
                game_cell = score_entry["element"]
                game_link_element = webpage.get_element(
                    parent = game_cell,
                    locator = webpage.ElementLocator({"tag": "a"}),
                    verbose = verbose,
                    exit_on_failure = False)
                if game_link_element:
                    appurl = webpage.get_element_attribute(game_link_element, "href")
                    if appurl:
                        appurl = strings.strip_string_query_params(appurl)
                        break
            return appurl

        # Use retry function with cleanup
        try:
            return webpage.retry_scrape(
                func = attempt_url_search,
                cleanup_func = cleanup_driver,
                verbose = verbose,
                operation_name = "Legacy store URL search for '%s'" % identifier)
        finally:
            cleanup_driver()

    ############################################################
    # Purchases
    ############################################################

    # Owned games as installer uuid and name from Heirloom's JSON list, skipping entries without a uuid
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get script command
        script_cmd = programs.get_python_script_command("Heirloom")
        if not script_cmd:
            return None

        # Get list command
        list_cmd = script_cmd + [
                        "list",
            "--json",
            "--quiet"
        ]

        # Run list command
        list_output = command.run_output_command(
            cmd = list_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not list_output:
            logger.log_error("Unable to find legacy purchases")
            return None

        # Get legacy json
        legacy_json = serialization.parse_json_or_none(list_output)
        if not isinstance(legacy_json, list):
            logger.log_error("Unable to parse legacy game list")
            logger.log_error("Received output:\n%s" % list_output)
            return None

        # Parse output
        purchases = []
        for entry in legacy_json:

            # Gather info
            if not isinstance(entry, dict):
                continue
            line_appid = get_json_string(entry, "installer_uuid")
            line_title = get_json_string(entry, "game_name")
            if not line_appid:
                continue

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.get_platform())
            purchase.set_value(config.JSON_KEY_STORE_APPID, line_appid)
            purchase.set_value(config.JSON_KEY_STORE_NAME, line_title)
            purchases.append(purchase)
        return purchases

    ############################################################
    # Json
    ############################################################

    # The game name from Heirloom's info for an installer uuid, plus manifest save paths; None when unknown
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

        # Get script command
        script_cmd = programs.get_python_script_command("Heirloom")
        if not script_cmd:
            return None

        # Get info command
        info_cmd = script_cmd + [
                        "info",
            "--uuid", identifier,
            "--quiet"
        ]

        # Run info command
        info_output = command.run_output_command(
            cmd = info_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not info_output or "No game information available" in info_output:
            logger.log_error("Unable to find legacy information for '%s'" % identifier)
            return None

        # Get legacy json
        legacy_json = serialization.parse_json_or_none(info_output)
        if not isinstance(legacy_json, dict):
            logger.log_error("Unable to parse legacy game information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.JSON_KEY_STORE_APPID, identifier)
        json_data.set_value(config.JSON_KEY_STORE_NAME, get_json_string(legacy_json, "game_name"))
        return self.augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Assets
    ############################################################

    # A box front from the metadata asset collectors, or the YouTube embed on the game page; None for other types
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
            latest_asset_url = metadataassetcollector.find_metadata_asset(
                game_platform = self.get_platform(),
                game_name = game_name if game_name else identifier,
                asset_type = asset_type,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = webfetch.get_matching_url(
                url = identifier,
                base_url = "https://www.bigfishgames.com",
                starts_with = "https://www.youtube.com/embed",
                ends_with = "enablejsapi=1",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Return latest asset url
        return latest_asset_url

    ############################################################
