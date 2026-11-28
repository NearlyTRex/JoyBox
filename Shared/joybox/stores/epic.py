# Imports
import types
import os

# Local imports
from joybox import config
from joybox import command
from joybox import programs
from joybox import serialization
from joybox import logger
from joybox import settings
from joybox import jsondata
from joybox import webpage
from joybox import storebase
from joybox import storepaths
from joybox import strings
from joybox import metadataentry
from joybox import paths

# Link of the best-scoring result at or above the match threshold that has one; None otherwise
def _find_best_result_link(scores_list, verbose = False):
    min_match_score = webpage.get_min_match_score()
    for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
        if score_entry["ratio"] < min_match_score:
            break
        game_cell = score_entry["element"]
        game_link_element = webpage.get_element(
            parent = game_cell,
            locator = webpage.ElementLocator({"class": "css-1k3j1r9"}),
            verbose = verbose)
        if game_link_element:
            return webpage.get_element_attribute(game_link_element, "href")
    return None

# Set developer, publisher or release date from one store page detail text
def _read_detail_text(element_detail_text, metadata_entry):

    # Developer
    if strings.does_string_start_with_substring(element_detail_text, "Developer"):
        developer_text = strings.trim_substring_from_start(element_detail_text, "Developer").strip()
        metadata_entry.set_developer(developer_text)
        return

    # Publisher
    if strings.does_string_start_with_substring(element_detail_text, "Publisher"):
        published_text = strings.trim_substring_from_start(element_detail_text, "Publisher").strip()
        metadata_entry.set_publisher(published_text)
        return

    # Release
    if strings.does_string_start_with_substring(element_detail_text, "Release Date"):
        release_text = strings.trim_substring_from_start(element_detail_text, "Release Date").strip()
        release_text = strings.convert_date_string(release_text, "%m/%d/%y", "%Y-%m-%d")
        if release_text:
            metadata_entry.set_release(release_text)

# Purchase fields for one Legendary list entry, with its Windows build version
def _create_owned_game_data(entry):
    windows_asset = (entry.get("asset_infos") or {}).get("Windows") or {}
    line_appname = str(entry.get("app_name") or "")
    line_title = str(entry.get("app_title") or "")
    line_buildid = str(windows_asset.get("build_version") or config.DEFAULT_BUILDID)
    return {
        config.JSON_KEY_STORE_APPNAME: line_appname,
        config.JSON_KEY_STORE_APPURL: "",
        config.JSON_KEY_STORE_NAME: line_title,
        config.JSON_KEY_STORE_BUILDID: line_buildid
    }

# Epic store
class Epic(storebase.StoreBase):

    TYPE = config.StoreType.EPIC
    PLATFORM = config.Platform.COMPUTER_EPIC_GAMES
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_EPIC_GAMES
    KEY = config.JSON_KEY_EPIC
    IDENTIFIER_KEYS = types.MappingProxyType({
        config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_NAME,
    })

    # Constructor
    def __init__(self):
        super().__init__()

        # Get user details
        self.username = settings.get_value("UserData.Epic", "epic_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get install dir
        self.load_install_dir("UserData.Epic", "epic_install_dir")

    ############################################################
    # Store
    ############################################################

    # The Epic username from the settings; the constructor refuses to build without one
    def get_user_name(self):
        return self.username

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

    # Get files the purchase listing's saved sign-in is kept in
    def get_login_files(self):
        config_dir = os.environ.get("LEGENDARY_CONFIG_PATH") or paths.join_paths(self.get_user_config_dir(), "legendary")
        return [paths.join_paths(config_dir, "user.json")]

    # Sign in through Legendary's interactive auth; True at once when already signed in
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Get script command
        script_cmd = programs.get_python_script_command("Legendary")
        if not script_cmd:
            return False

        # Get login command
        login_cmd = script_cmd + [
                        "auth"
        ]

        # Run login command
        return self.run_login_command(
            login_cmd = login_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Page
    ############################################################

    # Store page link found by searching the Epic store in a headless browser; None when nothing matches closely
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

        # Connect to web
        web_driver = self.web_connect(
            headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Search, then disconnect whatever the outcome
        try:
            return self.find_best_store_url(
                web_driver = web_driver,
                identifier = identifier,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        finally:
            self.web_disconnect(
                web_driver = web_driver,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Search the Epic store for the identifier and return the link of the closest title above the match threshold, else None
    def find_best_store_url(
        self,
        web_driver,
        identifier,
        verbose = False,
        exit_on_failure = False):

        # Get search terms
        search_terms = strings.encode_url_string(identifier.strip(), use_plus = True)

        # Load url
        success = webpage.load_url(web_driver, "https://store.epicgames.com/en-US/browse?sortBy=relevancy&sortDir=DESC&q=" + search_terms)
        if not success:
            return None

        # Find the root container element
        element_search_result = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "css-1ufzxyu"}),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not element_search_result:
            return None

        # Score each potential title compared to the original title
        scores_list = self._score_search_results(element_search_result, identifier, verbose = verbose)

        # Get the best url match among results close enough to the name
        return _find_best_result_link(scores_list, verbose = verbose)

    # Each search result cell with its title's similarity ratio to the identifier
    def _score_search_results(self, element_search_result, identifier, verbose = False):
        scores_list = []
        game_cells = webpage.get_element(
            parent = element_search_result,
            locator = webpage.ElementLocator({"class": "css-2mlzob"}),
            all_elements = True)
        for game_cell in game_cells or []:

            # Get possible title
            game_title_element = webpage.get_element(
                parent = game_cell,
                locator = webpage.ElementLocator({"class": "css-lgj0h8"}),
                verbose = verbose)
            game_cell_text = webpage.get_element_children_text(game_title_element)

            # Add comparison score
            score_entry = {}
            score_entry["element"] = game_cell
            score_entry["ratio"] = strings.get_string_similarity_ratio(identifier, game_cell_text)
            scores_list.append(score_entry)
        return scores_list

    ############################################################
    # Purchases
    ############################################################

    # Owned games with appname, title and Windows build, from a cache under a day old or else Legendary's list
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = self.get_purchases_cache_dir()
        cache_file_purchases = paths.join_paths(cache_dir, "epic_purchases_cache.json")

        # Load from cache if available
        cached_data = self.read_purchases_cache(cache_file_purchases, "Epic", verbose = verbose)
        if cached_data is not None:
            return self.make_purchases(cached_data)

        # Get epic json
        epic_json = self._list_owned_games(verbose = verbose, exit_on_failure = exit_on_failure)
        if epic_json is None:
            return None

        # Parse output
        purchases = []
        purchases_data = []
        for entry in epic_json:
            purchase_data = _create_owned_game_data(entry)
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.get_platform())
            for key, value in purchase_data.items():
                purchase.set_value(key, value)
            purchases.append(purchase)
            purchases_data.append(purchase_data)

        # Save to cache
        self.write_purchases_cache(cache_dir, cache_file_purchases, purchases_data, "Epic", verbose = verbose, pretend_run = pretend_run)
        return purchases

    # Legendary's JSON list of owned games; None, logged, when it gives no list
    def _list_owned_games(self, verbose = False, exit_on_failure = False):

        # Get script command
        script_cmd = programs.get_python_script_command("Legendary")
        if not script_cmd:
            return None

        # Get list command
        list_cmd = script_cmd + [
                        "list",
            "--json"
        ]

        # Run list command
        list_output = command.run_output_command(
            cmd = list_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not list_output:
            logger.log_error("Unable to find epic purchases")
            return None

        # Get epic json
        epic_json = serialization.parse_json_or_none(list_output)
        if not isinstance(epic_json, list):
            logger.log_error("Unable to parse epic game list")
            logger.log_error("Received output:\n%s" % list_output)
            return None
        return epic_json

    ############################################################
    # Json
    ############################################################

    # Appname, title, version and cloud save folder from Legendary's info; None when unknown
    def fetch_latest_jsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get game info
        del branch, pretend_run
        game_info = self._get_legendary_game_info(identifier, verbose = verbose, exit_on_failure = exit_on_failure)
        if game_info is None:
            return None

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.JSON_KEY_STORE_APPNAME, identifier)
        json_data.set_value(config.JSON_KEY_STORE_NAME, str(game_info.get("title") or "").strip())
        json_data.set_value(config.JSON_KEY_STORE_BUILDID, str(game_info.get("version") or config.DEFAULT_BUILDID).strip())
        cloud_save_folder = game_info.get("cloud_save_folder")
        if cloud_save_folder:
            json_data.set_value(config.JSON_KEY_STORE_PATHS, [
                storepaths.create_tokenized_path(cloud_save_folder.strip())
            ])
        return json_data

    # The "game" section of Legendary's info json for the appname; None, logged, when unavailable
    def _get_legendary_game_info(self, identifier, verbose = False, exit_on_failure = False):

        # Get script command
        script_cmd = programs.get_python_script_command("Legendary")
        if not script_cmd:
            return None

        # Get info command
        info_cmd = script_cmd + [
                        "info", identifier,
            "--json"
        ]

        # Run info command
        info_output = command.run_output_command(
            cmd = info_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not info_output or "No game information available" in info_output:
            logger.log_error("Unable to find epic information for '%s'" % identifier)
            return None

        # Get epic json
        epic_json = serialization.parse_json_or_none(info_output)
        game_info = epic_json.get("game") if isinstance(epic_json, dict) else None
        if not isinstance(game_info, dict):
            logger.log_error("Unable to parse epic game information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None
        return game_info

    ############################################################
    # Metadata
    ############################################################

    # Description, genres, developer, publisher and release date scraped from the game's store page, with retries
    def get_latest_metadata(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del exit_on_failure
        return self.scrape_latest_metadata(
            identifier = identifier,
            scrape_func = lambda web_driver: self._scrape_metadata_page(web_driver, identifier, verbose = verbose),
            store_label = "Epic",
            verbose = verbose,
            pretend_run = pretend_run)

    # Load the store page and read its description, genres and details into a metadata entry
    def _scrape_metadata_page(self, web_driver, identifier, verbose = False):

        # Load url
        self.load_scrape_page(web_driver, identifier)
        metadata_entry = metadataentry.MetadataEntry()

        # Look for game description
        game_description = self.wait_for_page_text(web_driver, {"id": "about-long-description"}, verbose = verbose)
        if game_description:
            metadata_entry.set_description(game_description)

        # Look for game genres
        self._read_page_genres(web_driver, metadata_entry, verbose = verbose)

        # Look for game details
        elements_details = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "css-s97i32"}),
            all_elements = True,
            verbose = verbose,
            exit_on_failure = False)
        for elements_detail in elements_details or []:
            element_detail_text = webpage.get_element_children_text(elements_detail)
            if element_detail_text:
                _read_detail_text(element_detail_text, metadata_entry)
        return metadata_entry

    # Set the entry's genres, joined with ";", from the page section headed "Genres"
    def _read_page_genres(self, web_driver, metadata_entry, verbose = False):
        elements_potential_genres = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "css-8f0505"}),
            all_elements = True,
            verbose = verbose,
            exit_on_failure = False)
        for element_potential_genre in elements_potential_genres or []:
            potential_text = webpage.get_element_children_text(element_potential_genre)
            if not potential_text or "Genres" not in potential_text:
                continue
            element_game_genres = webpage.get_element(
                parent = element_potential_genre,
                locator = webpage.ElementLocator({"class": "css-cyjj8t"}),
                all_elements = True,
                verbose = verbose,
                exit_on_failure = False)
            game_genres = []
            for element_game_genre in element_game_genres or []:
                game_genre_text = webpage.get_element_children_text(element_game_genre)
                if game_genre_text:
                    game_genres.append(game_genre_text)
            if game_genres:
                metadata_entry.set_genre(";".join(game_genres))

    ############################################################
