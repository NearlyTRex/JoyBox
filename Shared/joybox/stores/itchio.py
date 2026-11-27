# Imports
import time
import types

# Local imports
from joybox import config
from joybox import logger
from joybox import webpage
from joybox import webcookies
from joybox import webfetch
from joybox import storebase
from joybox import strings
from joybox import metadataentry
from joybox import paths
from joybox import settings
from joybox import runtime

# Longest the my-purchases grid may keep loading before the scrape gives up, in seconds
PURCHASES_LOAD_TIMEOUT_SECONDS = 300

# Info panel line labels in match order, with which metadata they fill
GAME_DETAIL_LABELS = (
    ("Release date", "release"),
    ("Published", "release"),
    ("Authors", "author"),
    ("Author", "author"),
    ("Genre", "genre"),
)

# Itchio store
class Itchio(storebase.StoreBase):

    TYPE = config.StoreType.ITCHIO
    PLATFORM = config.Platform.COMPUTER_ITCHIO
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_ITCHIO
    KEY = config.JSON_KEY_ITCHIO
    IDENTIFIER_KEYS = types.MappingProxyType({
        config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_APPURL,
    })

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = settings.get_path_value("UserData.Itchio", "itchio_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

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
        return [self.get_cookie_file()]

    # Sign in to itch.io in a visible browser and save its cookie file; True at once when already signed in
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Log into website
        success = self.run_with_web_driver(
            func = lambda web_driver: webcookies.login_cookie_website(
                driver = web_driver,
                url = "https://itch.io/login",
                cookie = self.get_cookie_file(),
                locator = webpage.ElementLocator({"link_text": "My feed"}),
                verbose = verbose),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Should be successful
        self.set_logged_in(True)
        return True

    ############################################################
    # Purchases
    ############################################################

    # Owned games with id, page and title, from a cache under a day old or else scraped from the my-purchases page
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = self.get_purchases_cache_dir()
        cache_file_purchases = paths.join_paths(cache_dir, "itchio_purchases_cache.json")

        # Load from cache if recent
        cached_data = self.read_purchases_cache(cache_file_purchases, "itch.io", verbose = verbose)
        if cached_data is not None:
            return self.make_purchases(cached_data)

        # Scrape purchases
        purchases_data = self._scrape_purchases_headless(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if purchases_data is None:
            return None

        # Save to cache
        self.write_purchases_cache(cache_dir, cache_file_purchases, purchases_data, "itch.io", verbose = verbose, pretend_run = pretend_run)

        # Return purchases
        return self.make_purchases(purchases_data)

    # Scrape the purchase dicts in a headless browser; None when it cannot connect, scrape or disconnect
    def _scrape_purchases_headless(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        return self.run_with_web_driver(
            func = lambda web_driver: self.scrape_purchases(
                web_driver = web_driver,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure),
            headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Scroll to the end of the page until its grid loader is gone; False when it is still there at the deadline
    def scroll_until_loaded(self, web_driver):
        deadline = time.monotonic() + PURCHASES_LOAD_TIMEOUT_SECONDS
        while True:
            webpage.scroll_to_end_of_page(web_driver)
            grid_loader = webpage.get_element(
                parent = web_driver,
                locator = webpage.ElementLocator({"class": "grid_loader"}))
            if grid_loader is None:
                return True
            if time.monotonic() > deadline:
                logger.log_error("itch.io purchases were still loading after %d seconds" % PURCHASES_LOAD_TIMEOUT_SECONDS)
                return False

    # Read id, page and title from every cell of the cookie-authenticated my-purchases page; None when it fails to load
    def scrape_purchases(
        self,
        web_driver,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Load url
        success = webcookies.load_cookie_website(
            driver = web_driver,
            url = "https://itch.io/my-purchases",
            cookie = self.get_cookie_file(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Scroll to end of page until everything is loaded
        if not self.scroll_until_loaded(web_driver):
            return None

        # Parse game cells
        purchases_data = []
        game_cells = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "game_cell"}),
            all_elements = True)
        for game_cell in game_cells or []:
            purchase_data = self._parse_purchase_cell(game_cell)
            if purchase_data:
                purchases_data.append(purchase_data)
        return purchases_data

    # Id, page (without any /download suffix) and title of one my-purchases cell; None without a titled link
    def _parse_purchase_cell(self, game_cell):
        game_title = webpage.get_element(
            parent = game_cell,
            locator = webpage.ElementLocator({"class": "title"}))
        if not game_title:
            return None

        # Gather info
        line_appid = webpage.get_element_attribute(game_cell, "data-game_id")
        line_appurl = webpage.get_element_attribute(game_title, "href")
        if not line_appurl:
            return None
        if len(line_appurl.split("/download")) == 2:
            line_appurl = line_appurl.split("/download")[0]
        line_title = (webpage.get_element_text(game_title) or "").rstrip(" \n")
        return {
            config.JSON_KEY_STORE_APPID: line_appid,
            config.JSON_KEY_STORE_APPURL: line_appurl,
            config.JSON_KEY_STORE_NAME: line_title
        }

    ############################################################
    # Metadata
    ############################################################

    # Description, release date, authors and genres scraped from the game page with the saved cookie, with retries
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

        # Scrape the game page with retries
        return self.scrape_with_retries(
            scrape_func = lambda web_driver: self._scrape_metadata_page(web_driver, identifier, verbose = verbose, pretend_run = pretend_run),
            operation_name = "Itch.io metadata fetch for '%s'" % identifier,
            verbose = verbose,
            pretend_run = pretend_run)

    # Load the game page with the saved cookie and read its metadata; ScrapeFailed when it does not load
    def _scrape_metadata_page(self, web_driver, identifier, verbose = False, pretend_run = False):

        # Load url with cookie
        success = webcookies.load_cookie_website(
            driver = web_driver,
            url = identifier,
            cookie = self.get_cookie_file(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not success:
            raise webpage.ScrapeFailed("Failed to load URL: %s" % identifier)

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()

        # Load more information if necessary
        element_more_information = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"xpath": "//div[@class='toggle_row']//a[contains(text(), 'More information')]"}),
            verbose = verbose,
            exit_on_failure = False)
        if element_more_information:
            webpage.click_element(element_more_information)
            runtime.sleep_program(3)

        # Read description and details
        self._read_game_description(web_driver, metadata_entry, verbose = verbose)
        self._read_game_details(web_driver, metadata_entry, verbose = verbose)
        return metadata_entry

    # Set the entry's description from the page's formatted description, when it has one
    def _read_game_description(self, web_driver, metadata_entry, verbose = False):

        # Look for game description
        element_game_description = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "formatted_description"}),
            verbose = verbose,
            exit_on_failure = False)
        if element_game_description:
            raw_game_description = webpage.get_element_text(element_game_description)
            if raw_game_description:
                metadata_entry.set_description(raw_game_description)

    # Apply each line of the page's info panel to the entry
    def _read_game_details(self, web_driver, metadata_entry, verbose = False):

        # Look for game details
        element_game_details = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "game_info_panel_widget"}),
            verbose = verbose,
            exit_on_failure = False)
        if not element_game_details:
            return
        raw_game_details = webpage.get_element_text(element_game_details)
        if not raw_game_details:
            return
        for game_detail_line in raw_game_details.split("\n"):
            self._apply_game_detail_line(metadata_entry, game_detail_line)

    # Set release, developer/publisher or genre from one info panel line, by its first matching label
    def _apply_game_detail_line(self, metadata_entry, game_detail_line):
        for detail_label, detail_kind in GAME_DETAIL_LABELS:
            if not strings.does_string_start_with_substring(game_detail_line, detail_label):
                continue
            detail_text = strings.trim_substring_from_start(game_detail_line, detail_label).strip()

            # Release
            if detail_kind == "release":
                metadata_entry.set_release(strings.convert_date_string(detail_text, "%b %d, %Y", "%Y-%m-%d"))

            # Developer/publisher
            elif detail_kind == "author":
                metadata_entry.set_developer(detail_text)
                metadata_entry.set_publisher(detail_text)

            # Genre
            else:
                metadata_entry.set_genre(detail_text.replace(", ", ";"))
            return

    ############################################################
    # Assets
    ############################################################

    # A box front found through the itch.io search, or the YouTube embed on the game page; None for other types
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
            latest_asset_url = self._search_cover_headless(
                identifier = identifier,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = webfetch.get_matching_url(
                url = identifier,
                base_url = "https://www.youtube.com/embed",
                starts_with = "https://www.youtube.com/embed",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Return latest asset url
        return latest_asset_url

    # Cover found by search_cover in a headless browser; None when it cannot connect or disconnect
    def _search_cover_headless(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        return self.run_with_web_driver(
            func = lambda web_driver: self.search_cover(
                web_driver = web_driver,
                identifier = identifier,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure),
            headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Search itch.io by the page's path and return the cover image of the result linking to that exact page, else None
    def search_cover(
        self,
        web_driver,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Load search page
        search_terms = strings.get_url_path(identifier).strip("/")
        success = webcookies.load_cookie_website(
            driver = web_driver,
            url = "https://itch.io/search?q=" + search_terms,
            cookie = self.get_cookie_file(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Find the root container element
        element_search_result = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "browse_game_grid"}),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not element_search_result:
            return None

        # Search through search results
        return self._find_matching_cover(element_search_result, identifier)

    # Cover image src of the search result whose title links to exactly identifier; None when none does
    def _find_matching_cover(self, element_search_result, identifier):
        game_cells = webpage.get_element(
            parent = element_search_result,
            locator = webpage.ElementLocator({"class": "game_cell"}),
            all_elements = True)
        for game_cell in game_cells or []:
            game_title = webpage.get_element(
                parent = game_cell,
                locator = webpage.ElementLocator({"class": "title"}))
            game_cover = webpage.get_element(
                parent = game_cell,
                locator = webpage.ElementLocator({"class": "lazy_loaded"}))
            if not game_title or not game_cover:
                continue
            if webpage.get_element_attribute(game_title, "href") == identifier:
                return webpage.get_element_attribute(game_cover, "src")
        return None

    ############################################################
