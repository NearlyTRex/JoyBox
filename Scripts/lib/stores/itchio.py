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

# Itchio store
class Itchio(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

    # Get name
    def GetName(self):
        return "Itchio"

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

        # Create web driver
        try:
            web_driver = webpage.CreateWebDriver(verbose = verbose)
        except Exception as e:
            if verbose:
                system.LogError(e)
            return False

        # Log into itchio
        success = webpage.LogIntoWebsite(
            driver = web_driver,
            login_url = config.itchio_login_url,
            cookiefile = os.path.join(environment.GetCookieDirectory(), config.itchio_login_cookie_filename),
            link_text = config.itchio_login_link_text,
            verbose = verbose)
        if not success:
            return False

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
            return False

        # Go to the purchases page
        try:
            web_driver.get("https://itch.io/my-purchases")
        except:
            return None

        # Scroll to end of page until everything is loaded
        webpage.ScrollToEndOfPage(web_driver)
        element_grid_loader = webpage.WaitForPageElement(web_driver, class_name = "grid_loader", verbose = verbose)
        while element_grid_loader:
            webpage.ScrollToEndOfPage(web_driver)
            element_grid_loader = webpage.WaitForPageElement(web_driver, class_name = "grid_loader", verbose = verbose)

        # Parse game cells
        purchases = []
        game_cells = webpage.GetElement(web_driver, class_name = "game_cell", all_elements = True)
        if game_cells:
            for game_cell in game_cells:
                game_title = webpage.GetElement(game_cell, class_name = "title", tag_name = "a")
                game_cover = webpage.GetElement(game_cell, class_name = "lazy_loaded", tag_name = "img")

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
                purchase.SetJsonValue(config.json_key_store_appid, line_appid)
                purchase.SetJsonValue(config.json_key_store_appurl, line_appurl)
                purchase.SetJsonValue(config.json_key_store_name, line_title)
                purchases.append(purchase)

        # Destroy web driver
        try:
            webpage.DestroyWebDriver(web_driver, verbose = verbose)
        except Exception as e:
            if verbose:
                system.LogError(e)
            return None

        # Return purchases
        return purchases

    ############################################################

    # Get info
    def GetLatestInfo(
        self,
        identifier,
        branch = None,
        verbose = False,
        exit_on_failure = False):
        return False

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
