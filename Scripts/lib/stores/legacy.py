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
import ini
import jsondata
import webpage
import storebase
import metadataentry
import metadatacollector

# Legacy store
class Legacy(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get user details
        self.username = ini.GetIniValue("UserData.Legacy", "legacy_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Legacy", "legacy_install_dir")
        if not system.IsPathValid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.LEGACY.val()

    # Get type
    def GetType(self):
        return config.StoreType.LEGACY

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_LEGACY_GAMES

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_LEGACY_GAMES

    # Get key
    def GetKey(self):
        return config.json_key_legacy

    # Get identifier keys
    def GetIdentifierKeys(self):
        return {
            config.StoreIdentifierType.INFO: config.json_key_store_appid,
            config.StoreIdentifierType.INSTALL: config.json_key_store_appid,
            config.StoreIdentifierType.LAUNCH: config.json_key_store_appid,
            config.StoreIdentifierType.DOWNLOAD: config.json_key_store_appid,
            config.StoreIdentifierType.ASSET: config.json_key_store_appurl,
            config.StoreIdentifierType.METADATA: config.json_key_store_name,
            config.StoreIdentifierType.PAGE: config.json_key_store_appid
        }

    # Get user name
    def GetUserName(self):
        return self.username

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    # Check if purchases can be imported
    def CanImportPurchases(self):
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

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return False

        # Get script
        heirloom_script = None
        if programs.IsToolInstalled("Heirloom"):
            heirloom_script = programs.GetToolProgram("Heirloom")
        if not heirloom_script:
            system.LogError("Heirloom was not found")
            return False

        # Get login command
        login_cmd = [
            python_tool,
            heirloom_script,
            "login"
        ]

        # Run login command
        code = command.RunBlockingCommand(
            cmd = login_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if (code != 0):
            return False

        # Get refresh command
        refresh_cmd = [
            python_tool,
            heirloom_script,
            "refresh"
        ]

        # Run refresh command
        code = command.RunBlockingCommand(
            cmd = refresh_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Should be successful
        self.SetLoggedIn(True)
        return True

    ############################################################
    # Page
    ############################################################

    # Get latest url
    def GetLatestUrl(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidPageIdentifier(identifier):
            system.LogWarning("Page identifier '%s' was not valid" % identifier)
            return None

        # Connect to web
        web_driver = self.WebConnect(
            headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Get search terms
        search_terms = system.EncodeUrlString(identifier.strip(), use_plus = True)

        # Load url
        success = webpage.LoadUrl(web_driver, "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=" + search_terms)
        if not success:
            return None

        # Find the root container element
        element_search_result = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "productcollection__root"}),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not element_search_result:
            return None

        # Score each potential title compared to the original title
        scores_list = []
        game_cells = webpage.GetElement(
            parent = element_search_result,
            locator = webpage.ElementLocator({"class": "productcollection__items"}),
            all_elements = True)
        if game_cells:
            for game_cell in game_cells:
                game_title_element = webpage.GetElement(
                    parent = game_cell,
                    locator = webpage.ElementLocator({"class": "productcollection__item-title"}),
                    verbose = verbose)
                game_cell_text = webpage.GetElementChildrenText(game_title_element)

                # Add comparison score
                score_entry = {}
                score_entry["element"] = game_cell
                score_entry["ratio"] = system.GetStringSimilarityRatio(identifier, game_cell_text)
                scores_list.append(score_entry)

        # Get the best url match
        appurl = None
        for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
            game_cell = score_entry["element"]
            game_link_element = webpage.GetElement(
                parent = game_cell,
                locator = webpage.ElementLocator({"tag": "a"}),
                verbose = verbose)
            if game_link_element:
                appurl = webpage.GetElementAttribute(game_link_element, "href")
                appurl = system.StripStringQueryParams(appurl)
                break

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Return appurl
        return appurl

    ############################################################
    # Purchases
    ############################################################

    # Get purchases
    def GetLatestPurchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return None

        # Get script
        heirloom_script = None
        if programs.IsToolInstalled("Heirloom"):
            heirloom_script = programs.GetToolProgram("Heirloom")
        if not heirloom_script:
            system.LogError("Heirloom was not found")
            return None

        # Get list command
        list_cmd = [
            python_tool,
            heirloom_script,
            "list",
            "--json",
            "--quiet"
        ]

        # Run list command
        list_output = command.RunOutputCommand(
            cmd = list_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if len(list_output) == 0:
            system.LogError("Unable to find legacy purchases")
            return None

        # Get legacy json
        legacy_json = []
        try:
            legacy_json = json.loads(list_output)
        except Exception as e:
            system.LogError(e)
            system.LogError("Unable to parse legacy game list")
            system.LogError("Received output:\n%s" % info_output)
            return None

        # Parse output
        purchases = []
        for entry in legacy_json:

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.GetPlatform())
            if "installer_uuid" in entry:
                purchase.set_value(config.json_key_store_appid, entry["installer_uuid"].strip())
            if "game_name" in entry:
                purchase.set_value(config.json_key_store_name, entry["game_name"].strip())
            purchases.append(purchase)
        return purchases

    ############################################################
    # Json
    ############################################################

    # Get latest jsondata
    def GetLatestJsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidInfoIdentifier(identifier):
            system.LogWarning("Info identifier '%s' was not valid" % identifier)
            return None

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return None

        # Get script
        heirloom_script = None
        if programs.IsToolInstalled("Heirloom"):
            heirloom_script = programs.GetToolProgram("Heirloom")
        if not heirloom_script:
            system.LogError("Heirloom was not found")
            return None

        # Get info command
        info_cmd = [
            python_tool,
            heirloom_script,
            "info",
            "--uuid", identifier,
            "--quiet"
        ]

        # Run info command
        info_output = command.RunOutputCommand(
            cmd = info_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0 or "No game information available" in info_output:
            system.LogError("Unable to find legacy information for '%s'" % identifier)
            return None

        # Get legacy json
        legacy_json = {}
        try:
            legacy_json = json.loads(info_output)
        except Exception as e:
            system.LogError(e)
            system.LogError("Unable to parse legacy game info")
            system.LogError("Received output:\n%s" % info_output)
            return None

        # Build jsondata
        json_data = jsondata.JsonData({}, self.GetPlatform())
        json_data.set_value(config.json_key_store_appid, identifier)

        # Augment by json
        if "game_name" in legacy_json:
            json_data.set_value(config.json_key_store_name, legacy_json["game_name"].strip())

        # Return jsondata
        return json_data

    ############################################################
    # Assets
    ############################################################

    # Get latest asset url
    def GetLatestAssetUrl(
        self,
        identifier,
        asset_type,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidAssetIdentifier(identifier):
            system.LogWarning("Asset identifier '%s' was not valid" % identifier)
            return None

        # Latest asset url
        latest_asset_url = None

        # Video
        if asset_type == config.AssetType.VIDEO:
            latest_asset_url = webpage.GetMatchingUrl(
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
