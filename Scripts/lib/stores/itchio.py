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
import collection
import storebase
import metadataentry

# Itchio store
class Itchio(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

    # Get name
    def GetName(self):
        return config.StoreType.ITCHIO.val()

    # Get type
    def GetType(self):
        return config.StoreType.ITCHIO

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_ITCHIO

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_ITCHIO

    # Get key
    def GetKey(self):
        return config.json_key_itchio

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        return json_wrapper.get_value(config.json_key_store_appurl)

    ############################################################

    # Login
    def Login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return False

        # Log into website
        success = webpage.LoginCookieWebsite(
            driver = web_driver,
            url = "https://itch.io/login",
            cookie = self.GetCookieFile(),
            locator = webpage.ElementLocator({"link_text": "My feed"}),
            verbose = verbose)
        if not success:
            return None

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################

    # Get purchases
    def GetPurchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Load url
        success = webpage.LoadCookieWebsite(
            driver = web_driver,
            url = "https://itch.io/my-purchases",
            cookie = self.GetCookieFile(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Scroll to end of page until everything is loaded
        while True:
            webpage.ScrollToEndOfPage(web_driver)
            grid_loader = webpage.GetElement(
                parent = web_driver,
                locator = webpage.ElementLocator({"class": "grid_loader"}))
            if grid_loader is None:
               break

        # Parse game cells
        purchases = []
        game_cells = webpage.GetElement(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "game_cell"}),
            all_elements = True)
        if game_cells:
            for game_cell in game_cells:
                game_title = webpage.GetElement(
                    parent = game_cell,
                    locator = webpage.ElementLocator({"class": "title"}))
                game_cover = webpage.GetElement(
                    parent = game_cell,
                    locator = webpage.ElementLocator({"class": "lazy_loaded"}))
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
            web_driver = web_driver,
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
        pretend_run = False,
        exit_on_failure = False):
        return None

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
        success = webpage.LoadCookieWebsite(
            driver = web_driver,
            url = identifier,
            cookie = self.GetCookieFile(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()

        # Load more information if necessary
        element_more_information = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"xpath": "//div[@class='toggle_row']//a[contains(text(), 'More information')]"}),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if element_more_information:
            webpage.ClickElement(element_more_information)
            system.SleepProgram(3)

        # Look for game description
        element_game_description = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "formatted_description"}),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if element_game_description:
            raw_game_description = webpage.GetElementText(element_game_description)
            if raw_game_description:
                metadata_entry.set_description(raw_game_description)

        # Look for game details
        element_game_details = webpage.GetElement(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "game_info_panel_widget"}))
        if element_game_details:
            raw_game_details = webpage.GetElementText(element_game_details)
            for game_detail_line in raw_game_details.split("\n"):

                # Release
                if system.DoesStringStartWithSubstring(game_detail_line, "Release date"):
                    release_text = system.TrimSubstringFromStart(game_detail_line, "Release date").strip()
                    release_text = system.ConvertDateString(release_text, "%b %d, %Y", "%Y-%m-%d")
                    metadata_entry.set_release(release_text)
                if system.DoesStringStartWithSubstring(game_detail_line, "Published"):
                    release_text = system.TrimSubstringFromStart(game_detail_line, "Published").strip()
                    release_text = system.ConvertDateString(release_text, "%b %d, %Y", "%Y-%m-%d")
                    metadata_entry.set_release(release_text)

                # Developer/publisher
                elif system.DoesStringStartWithSubstring(game_detail_line, "Authors"):
                    author_text = system.TrimSubstringFromStart(game_detail_line, "Authors").strip()
                    metadata_entry.set_developer(author_text)
                    metadata_entry.set_publisher(author_text)
                elif system.DoesStringStartWithSubstring(game_detail_line, "Author"):
                    author_text = system.TrimSubstringFromStart(game_detail_line, "Author").strip()
                    metadata_entry.set_developer(author_text)
                    metadata_entry.set_publisher(author_text)

                # Genre
                elif system.DoesStringStartWithSubstring(game_detail_line, "Genre"):
                    genre_text = system.TrimSubstringFromStart(game_detail_line, "Genre").strip().replace(", ", ";")
                    metadata_entry.set_genre(genre_text)

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
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
        pretend_run = False,
        exit_on_failure = False):
        return []

    ############################################################

    # Install by identifier
    def InstallByIdentifier(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    ############################################################

    # Launch by identifier
    def LaunchByIdentifier(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
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
        pretend_run = False,
        exit_on_failure = False):
        return False

    ############################################################

    # Download asset
    def DownloadAsset(
        self,
        game_info,
        asset_type,
        force = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if asset exists
        asset_exists = collection.DoesMetadataAssetExist(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            asset_type = asset_type)

        # Check if asset should be downloaded
        should_download = False
        if force or not asset_exists:
            should_download = True
        if not should_download:
            return True

        # Latest asset url
        latest_asset_url = None

        # BoxFront
        if asset_type == config.AssetType.BOXFRONT:

            # Connect to web
            web_driver = self.WebConnect(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not web_driver:
                return False

            # Get search terms
            search_terms = system.EncodeUrlString(game_info.get_store_name(self.GetKey()), use_plus = True)

            # Load url
            success = webpage.LoadCookieWebsite(
                driver = web_driver,
                url = "https://itch.io/search?q=" + search_terms,
                cookie = self.GetCookieFile(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

            # Find the root container element
            element_search_result = webpage.WaitForElement(
                driver = web_driver,
                locator = webpage.ElementLocator({"class": "browse_game_grid"}),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not element_search_result:
                return False

            # Search through search results
            game_cells = webpage.GetElement(
                parent = element_search_result,
                locator = webpage.ElementLocator({"class": "game_cell"}),
                all_elements = True)
            if game_cells:
                for game_cell in game_cells:
                    game_title = webpage.GetElement(
                        parent = game_cell,
                        locator = webpage.ElementLocator({"class": "title"}))
                    game_cover = webpage.GetElement(
                        parent = game_cell,
                        locator = webpage.ElementLocator({"class": "lazy_loaded"}))
                    if not game_title or not game_cover:
                        continue

                    # Check for cover
                    line_appurl = webpage.GetElementAttribute(game_title, "href")
                    line_cover = webpage.GetElementAttribute(game_cover, "src")
                    if line_appurl == game_info.get_store_appurl(self.GetKey()):
                        latest_asset_url = line_cover
                        break

            # Disconnect from web
            success = self.WebDisconnect(
                web_driver = web_driver,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

        # Check if asset url is valid
        if not latest_asset_url:
            return False

        # Download metadata asset
        success = collection.DownloadMetadataAsset(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            asset_url = latest_asset_url,
            asset_type = asset_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Update metadata entry
        success = collection.UpdateMetadataEntry(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################
