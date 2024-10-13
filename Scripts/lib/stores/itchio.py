# Imports
import os, os.path
import sys
import json

# Local imports
import config
import command
import archive
import programs
import system
import environment
import hashing
import jsondata
import webpage
import storebase
import metadataentry

# Itchio store
class Itchio(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

    # Get name
    def GetName(self):
        return "Itchio"

    # Get type
    def GetType(self):
        return config.store_type_itchio

    # Get platform
    def GetPlatform(self):
        return config.platform_computer_itchio

    # Get category
    def GetCategory(self):
        return config.game_category_computer

    # Get subcategory
    def GetSubcategory(self):
        return config.game_subcategory_itchio

    # Get key
    def GetKey(self):
        return config.json_key_itchio

    # Get identifier
    def GetIdentifier(self, game_info, identifier_type):
        return game_info.get_store_appurl(self.GetKey())

    ############################################################

    # Login
    def Login(
        self,
        verbose = False,
        exit_on_failure = False):

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return False

        # Disconnect from web
        success = self.WebDisconnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return success

    # Web connect
    def WebConnect(
        self,
        verbose = False,
        exit_on_failure = False):

        # Create web driver
        try:
            web_driver = webpage.CreateWebDriver(verbose = verbose)
        except Exception as e:
            if verbose:
                system.LogError(e)
            return None

        # Log into itchio
        success = webpage.LogIntoWebsite(
            driver = web_driver,
            login_url = config.itchio_login_url,
            cookiefile = os.path.join(environment.GetCookieDirectory(), config.itchio_login_cookie_filename),
            link_text = config.itchio_login_link_text,
            verbose = verbose)
        if not success:
            return None

        # Return web driver
        return web_driver

    # Web disconnect
    def WebDisconnect(
        self,
        verbose = False,
        exit_on_failure = False):

        # Destroy web driver
        try:
            webpage.DestroyWebDriver(web_driver, verbose = verbose)
            return True
        except Exception as e:
            if verbose:
                system.LogError(e)
            return False

    ############################################################

    # Get purchases
    def GetPurchases(
        self,
        verbose = False,
        exit_on_failure = False):

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Go to the purchases page
        try:
            web_driver.get("https://itch.io/my-purchases")
        except:
            return None

        # Scroll to end of page until everything is loaded
        while True:
            webpage.ScrollToEndOfPage(web_driver)
            grid_loader = webpage.GetElement(web_driver, class_name = "grid_loader", tag_name = "div")
            if grid_loader is None:
               break

        # Parse game cells
        purchases = []
        game_cells = webpage.GetElement(web_driver, class_name = "game_cell", all_elements = True)
        if game_cells:
            for game_cell in game_cells:
                game_title = webpage.GetElement(game_cell, class_name = "title", tag_name = "a")
                game_cover = webpage.GetElement(game_cell, class_name = "lazy_loaded", tag_name = "img")
                if not game_title or not game_cover:
                    continue

                # Gather info
                line_appid = webpage.GetElementAttribute(game_cell, "data-game_id")
                line_appurl = webpage.GetElementAttribute(game_title, "href")
                if len(line_appurl.split("/download")) == 2:
                    line_appurl = line_appurl.split("/download")[0]
                line_title = webpage.GetElementText(game_title).rstrip(" \n")

                # Create purchase
                purchase = jsondata.JsonData(
                    json_data = {},
                    json_platform = self.GetPlatform())
                purchase.set_value(config.json_key_store_appid, line_appid)
                purchase.set_value(config.json_key_store_appurl, line_appurl)
                purchase.set_value(config.json_key_store_name, line_title)
                purchases.append(purchase)

        # Disconnect from web
        success = self.WebDisconnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Return purchases
        return purchases

    ############################################################

    # Get latest jsondata
    def GetLatestJsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        exit_on_failure = False):
        return None

    ############################################################

    # Get latest metadata
    def GetLatestMetadata(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Go to the search page and pull the results
        try:
            web_driver.get(identifier)
        except:
            return None

        # Look for game description
        section_game_description = webpage.WaitForPageElement(web_driver, class_name = "formatted_description", verbose = verbose)
        if not section_game_description:
            return None

        # Look for game information
        section_game_information = webpage.WaitForPageElement(web_driver, class_name = "more_information_toggle", verbose = verbose)
        if not section_game_information:
            return None

        # Grab the description text
        raw_game_description = webpage.GetElementText(section_game_description)

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()

        # Convert description to metadata format
        if raw_game_description:
            metadata_entry.set_description(CleanRawGameDescription(raw_game_description))

        # Grab the information text
        raw_game_information = webpage.GetElementText(section_game_information)

        # Click the "More information" button if it's present
        if raw_game_information:
            if "More information" in raw_game_information:
                element_game_info_more = webpage.GetElement(web_driver, link_text = "More information")
                if element_game_info_more:
                    webpage.ClickElement(element_game_info_more)

        # Wait for more information to load
        time.sleep(3)

        # Look for game details
        section_game_details = webpage.GetElement(web_driver, class_name = "game_info_panel_widget")
        if section_game_details:

            # Grab the information text
            raw_game_details = webpage.GetElementText(section_game_details)
            for game_detail_line in raw_game_details.split("\n"):

                # Release
                if game_detail_line.startswith("Release date"):
                    release_text = game_detail_line.replace("Release date", "").strip()
                    release_time = datetime.datetime.strptime(release_text, "%b %d, %Y")
                    metadata_entry.set_release(release_time.strftime("%Y-%m-%d"))
                if game_detail_line.startswith("Published"):
                    release_text = game_detail_line.replace("Published", "").strip()
                    release_time = datetime.datetime.strptime(release_text, "%b %d, %Y")
                    metadata_entry.set_release(release_time.strftime("%Y-%m-%d"))

                # Developer/publisher
                elif game_detail_line.startswith("Authors"):
                    author_text = game_detail_line.replace("Authors", "").strip()
                    metadata_entry.set_developer(author_text)
                    metadata_entry.set_publisher(author_text)
                elif game_detail_line.startswith("Author"):
                    author_text = game_detail_line.replace("Author", "").strip()
                    metadata_entry.set_developer(author_text)
                    metadata_entry.set_publisher(author_text)

                # Genre
                elif game_detail_line.startswith("Genre"):
                    metadata_entry.set_genre(game_detail_line.replace("Genre", "").strip().replace(", ", ";"))

        # Disconnect from web
        success = self.WebDisconnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Return metadata entry
        return metadata_entry

    ############################################################

    # Get game save paths
    def GetGameSavePaths(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):
        return []

    ############################################################

    # Install by identifier
    def InstallByIdentifier(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):
        return False

    ############################################################

    # Launch by identifier
    def LaunchByIdentifier(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):
        return False

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
        exit_on_failure = False):
        return False

    ############################################################
