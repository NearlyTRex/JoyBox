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
import ini

# Itchio store
class Itchio(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Itchio", "itchio_install_dir")
        if not system.IsPathValid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

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

    # Get identifier keys
    def GetIdentifierKeys(self):
        return {
            config.StoreIdentifierType.INFO: config.json_key_store_appurl,
            config.StoreIdentifierType.INSTALL: config.json_key_store_appurl,
            config.StoreIdentifierType.LAUNCH: config.json_key_store_appurl,
            config.StoreIdentifierType.DOWNLOAD: config.json_key_store_appurl,
            config.StoreIdentifierType.ASSET: config.json_key_store_appurl,
            config.StoreIdentifierType.METADATA: config.json_key_store_appurl,
            config.StoreIdentifierType.PAGE: config.json_key_store_appurl
        }

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    # Check if purchases can be imported
    def CanImportPurchases(self):
        return True

    # Check if purchases can be downloaded
    def CanDownloadPurchases(self):
        return True

    ############################################################
    # Connection
    ############################################################

    # Login
    def Login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.IsLoggedIn():
            return True

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
        if not success:
            return False

        # Should be successful
        self.SetLoggedIn(True)
        return True

    ############################################################
    # Purchases
    ############################################################

    # Get purchases
    def GetLatestPurchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = environment.GetCacheRootDir()
        cache_file_purchases = system.JoinPaths(cache_dir, "itchio_purchases_cache.json")

        # Check if cache exists and is recent (less than 24 hours old)
        use_cache = False
        if system.DoesPathExist(cache_file_purchases):
            cache_age_hours = system.GetFileAgeInHours(cache_file_purchases)
            if cache_age_hours < 24:
                use_cache = True
                if verbose:
                    system.LogInfo("Using cached itch.io purchases data (%.1f hours old)" % cache_age_hours)

        # Load from cache if available
        if use_cache:
            cached_data = system.ReadJsonFile(
                src = cache_file_purchases,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if cached_data and isinstance(cached_data, list):
                cached_purchases = []
                for purchase_data in cached_data:
                    purchase = jsondata.JsonData(
                        json_data = purchase_data,
                        json_platform = self.GetPlatform())
                    cached_purchases.append(purchase)
                return cached_purchases
            else:
                if verbose:
                    system.LogWarning("Failed to load itch.io cache, will fetch fresh data")
                use_cache = False

        # Connect to web
        web_driver = self.WebConnect(
            headless = True,
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
        purchases_data = []
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

                # Store data for caching
                purchases_data.append({
                    config.json_key_store_appid: line_appid,
                    config.json_key_store_appurl: line_appurl,
                    config.json_key_store_name: line_title
                })

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Save to cache
        system.MakeDirectory(cache_dir, verbose = verbose, pretend_run = pretend_run)
        success = system.WriteJsonFile(
            src = cache_file_purchases,
            json_data = purchases_data,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if success and verbose:
            system.LogInfo("Saved itch.io purchases data to cache")
        elif not success and verbose:
            system.LogWarning("Failed to save itch.io cache")

        # Return purchases
        return purchases

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

        # Store web driver for cleanup
        web_driver = None

        # Cleanup function
        def cleanup_driver():
            if web_driver:
                self.WebDisconnect(
                    web_driver = web_driver,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)

        # Fetch function
        def attempt_metadata_fetch():
            nonlocal web_driver

            # Connect to web
            web_driver = self.WebConnect(
                headless = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not web_driver:
                raise Exception("Failed to connect to web driver")

            # Load url with cookie
            success = webpage.LoadCookieWebsite(
                driver = web_driver,
                url = identifier,
                cookie = self.GetCookieFile(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not success:
                raise Exception("Failed to load URL: %s" % identifier)

            # Create metadata entry
            metadata_entry = metadataentry.MetadataEntry()

            # Load more information if necessary
            element_more_information = webpage.WaitForElement(
                driver = web_driver,
                locator = webpage.ElementLocator({"xpath": "//div[@class='toggle_row']//a[contains(text(), 'More information')]"}),
                wait_time = 15,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if element_more_information:
                webpage.ClickElement(element_more_information)
                system.SleepProgram(3)

            # Look for game description
            element_game_description = webpage.WaitForElement(
                driver = web_driver,
                locator = webpage.ElementLocator({"class": "formatted_description"}),
                wait_time = 15,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if element_game_description:
                raw_game_description = webpage.GetElementText(element_game_description)
                if raw_game_description:
                    metadata_entry.set_description(raw_game_description)

            # Look for game details
            element_game_details = webpage.GetElement(
                parent = web_driver,
                locator = webpage.ElementLocator({"class": "game_info_panel_widget"}),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if element_game_details:
                raw_game_details = webpage.GetElementText(element_game_details)
                if raw_game_details:
                    for game_detail_line in raw_game_details.split("\n"):

                        # Release
                        if system.DoesStringStartWithSubstring(game_detail_line, "Release date"):
                            release_text = system.TrimSubstringFromStart(game_detail_line, "Release date").strip()
                            release_text = system.ConvertDateString(release_text, "%b %d, %Y", "%Y-%m-%d")
                            metadata_entry.set_release(release_text)
                        elif system.DoesStringStartWithSubstring(game_detail_line, "Published"):
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
            return metadata_entry

        # Use retry function with cleanup
        result = system.RetryWithBackoff(
            func = attempt_metadata_fetch,
            cleanup_func = cleanup_driver,
            max_retries = 3,
            initial_delay = 2,
            backoff_factor = 2,
            verbose = verbose,
            operation_name = "Itch.io metadata fetch for '%s'" % identifier)

        # Final cleanup
        cleanup_driver()
        return result

    ############################################################
    # Assets
    ############################################################

    # Get latest asset url
    def GetLatestAssetUrl(
        self,
        identifier,
        asset_type,
        game_name = None,
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

            # Connect to web
            web_driver = self.WebConnect(
                headless = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not web_driver:
                return None

            # Get search terms
            search_terms = system.GetUrlPath(identifier).strip("/")

            # Load url
            success = webpage.LoadCookieWebsite(
                driver = web_driver,
                url = "https://itch.io/search?q=" + search_terms,
                cookie = self.GetCookieFile(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return None

            # Find the root container element
            element_search_result = webpage.WaitForElement(
                driver = web_driver,
                locator = webpage.ElementLocator({"class": "browse_game_grid"}),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not element_search_result:
                return None

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
                    if line_appurl == identifier:
                        latest_asset_url = line_cover
                        break

            # Disconnect from web
            success = self.WebDisconnect(
                web_driver = web_driver,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                return None

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = webpage.GetMatchingUrl(
                url = identifier,
                base_url = "https://www.youtube.com/embed",
                starts_with = "https://www.youtube.com/embed",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Return latest asset url
        return latest_asset_url

    ############################################################
