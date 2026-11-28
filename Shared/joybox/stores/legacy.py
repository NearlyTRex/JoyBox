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
from joybox import storebase
from joybox import strings

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
    PAGE_VIDEO_BASE_URL = "https://www.bigfishgames.com"
    PAGE_VIDEO_ENDS_WITH = "enablejsapi=1"
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
        self.load_install_dir("UserData.Legacy", "legacy_install_dir")

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

        # Log in, then refresh
        for subcommand in ("login", "refresh"):
            code = self._run_interactive_subcommand(
                script_cmd = script_cmd,
                subcommand = subcommand,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if code != 0:
                return False

        # Should be successful
        self.set_logged_in(True)
        return True

    # Run one interactive Heirloom step (login or refresh); returns its exit code
    def _run_interactive_subcommand(
        self,
        script_cmd,
        subcommand,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get subcommand command
        subcommand_cmd = script_cmd + [
                        subcommand
        ]

        # Run subcommand command
        return command.run_interactive_command(
            cmd = subcommand_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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

        # Search the store with retries
        return self.scrape_with_retries(
            scrape_func = lambda web_driver: self._search_store_url(web_driver, identifier, verbose = verbose),
            operation_name = "Legacy store URL search for '%s'" % identifier,
            verbose = verbose,
            pretend_run = pretend_run)

    # Search Big Fish Games for the title and return the best close match's page; ScrapeFailed when the search does not load
    def _search_store_url(self, web_driver, identifier, verbose = False):

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

        # Score results and pick the best url
        scores_list = self._score_search_results(element_search_result, identifier, verbose = verbose)
        return self._get_best_match_url(scores_list, verbose = verbose)

    # Similarity of each titled search result to the title, as element/ratio entries
    def _score_search_results(self, element_search_result, identifier, verbose = False):

        # Score each potential title compared to the original title
        scores_list = []
        game_cells = webpage.get_element(
            parent = element_search_result,
            locator = webpage.ElementLocator({"class": "productcollection__items"}),
            all_elements = True,
            verbose = verbose,
            exit_on_failure = False)
        for game_cell in game_cells or []:
            game_title_element = webpage.get_element(
                parent = game_cell,
                locator = webpage.ElementLocator({"class": "productcollection__item-title"}),
                verbose = verbose,
                exit_on_failure = False)
            if not game_title_element:
                continue
            game_cell_text = webpage.get_element_children_text(game_title_element)
            if not game_cell_text:
                continue

            # Add comparison score
            score_entry = {}
            score_entry["element"] = game_cell
            score_entry["ratio"] = strings.get_string_similarity_ratio(identifier, game_cell_text)
            scores_list.append(score_entry)
        return scores_list

    # Link of the highest-scoring result at or above the minimum match score, query stripped; None when none has one
    def _get_best_match_url(self, scores_list, verbose = False):

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
        return self._create_purchases(legacy_json)

    # Purchases with installer uuid and name for each list entry, skipping entries without a uuid
    def _create_purchases(self, legacy_json):
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

    # The game name from Heirloom's info for an installer uuid; None when unknown
    def fetch_latest_jsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get script command
        del branch, pretend_run
        script_cmd = programs.get_python_script_command("Heirloom")
        if not script_cmd:
            return None

        # Get legacy json
        legacy_json = self._fetch_game_info(
            script_cmd = script_cmd,
            identifier = identifier,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if legacy_json is None:
            return None

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.JSON_KEY_STORE_APPID, identifier)
        json_data.set_value(config.JSON_KEY_STORE_NAME, get_json_string(legacy_json, "game_name"))
        return json_data

    # Heirloom's info for an installer uuid as a dict; None (after logging) when unknown or unparsable
    def _fetch_game_info(
        self,
        script_cmd,
        identifier,
        verbose = False,
        exit_on_failure = False):

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
        return legacy_json

    ############################################################
