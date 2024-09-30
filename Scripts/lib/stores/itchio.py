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
        return game_info.get_store_appid(self.GetKey())

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
        if not web_driver:
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
        return None

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
