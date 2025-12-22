# Imports
import os, os.path
import sys
import json

# Local imports
import config
import datautils
import command
import archive
import programs
import system
import logger
import ini
import jsondata
import webpage
import storebase
import strings
import metadataentry
import paths
import metadatacollector
import metadataassetcollector

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
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def get_name(self):
        return config.StoreType.LEGACY.val()

    # Get type
    def get_type(self):
        return config.StoreType.LEGACY

    # Get platform
    def get_platform(self):
        return config.Platform.COMPUTER_LEGACY_GAMES

    # Get supercategory
    def get_supercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def get_category(self):
        return config.Category.COMPUTER

    # Get subcategory
    def get_subcategory(self):
        return config.Subcategory.COMPUTER_LEGACY_GAMES

    # Get key
    def get_key(self):
        return config.json_key_legacy

    # Get identifier keys
    def get_identifier_keys(self):
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
    def get_user_name(self):
        return self.username

    # Get install dir
    def get_install_dir(self):
        return self.install_dir

    # Check if purchases can be imported
    def can_import_purchases(self):
        return True

    # Check if purchases can be downloaded
    def can_download_purchases(self):
        return True

    ############################################################
    # Connection
    ############################################################

    # Login
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return False

        # Get script
        heirloom_script = None
        if programs.IsToolInstalled("Heirloom"):
            heirloom_script = programs.GetToolProgram("Heirloom")
        if not heirloom_script:
            logger.log_error("Heirloom was not found")
            return False

        # Get login command
        login_cmd = [
            python_tool,
            heirloom_script,
            "login"
        ]

        # Run login command
        code = command.RunInteractiveCommand(
            cmd = login_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
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
        code = command.RunInteractiveCommand(
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

    # Get latest url
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
            if web_driver:
                self.web_disconnect(
                    web_driver = web_driver,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)

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
                raise Exception("Failed to connect to web driver")

            # Get search terms
            search_terms = strings.encode_url_string(identifier.strip(), use_plus = True)

            # Load url
            success = webpage.LoadUrl(web_driver, "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=" + search_terms)
            if not success:
                raise Exception("Failed to load search URL")

            # Find the root container element
            element_search_result = webpage.WaitForElement(
                driver = web_driver,
                locator = webpage.ElementLocator({"class": "productcollection__root"}),
                wait_time = 15,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not element_search_result:
                return None  # No search results found, not an error

            # Score each potential title compared to the original title
            scores_list = []
            game_cells = webpage.GetElement(
                parent = element_search_result,
                locator = webpage.ElementLocator({"class": "productcollection__items"}),
                all_elements = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if game_cells:
                for game_cell in game_cells:
                    game_title_element = webpage.GetElement(
                        parent = game_cell,
                        locator = webpage.ElementLocator({"class": "productcollection__item-title"}),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = False)
                    if game_title_element:
                        game_cell_text = webpage.GetElementChildrenText(game_title_element)
                        if game_cell_text:
                            # Add comparison score
                            score_entry = {}
                            score_entry["element"] = game_cell
                            score_entry["ratio"] = strings.get_string_similarity_ratio(identifier, game_cell_text)
                            scores_list.append(score_entry)

            # Get the best url match
            appurl = None
            for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
                game_cell = score_entry["element"]
                game_link_element = webpage.GetElement(
                    parent = game_cell,
                    locator = webpage.ElementLocator({"tag": "a"}),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if game_link_element:
                    appurl = webpage.GetElementAttribute(game_link_element, "href")
                    if appurl:
                        appurl = strings.strip_string_query_params(appurl)
                        break
            return appurl

        # Use retry function with cleanup
        result = datautils.retry_with_backoff(
            func = attempt_url_search,
            cleanup_func = cleanup_driver,
            max_retries = 3,
            initial_delay = 2,
            backoff_factor = 2,
            verbose = verbose,
            operation_name = "Legacy store URL search for '%s'" % identifier)

        # Final cleanup
        cleanup_driver()
        return result

    ############################################################
    # Purchases
    ############################################################

    # Get purchases
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return None

        # Get script
        heirloom_script = None
        if programs.IsToolInstalled("Heirloom"):
            heirloom_script = programs.GetToolProgram("Heirloom")
        if not heirloom_script:
            logger.log_error("Heirloom was not found")
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
            logger.log_error("Unable to find legacy purchases")
            return None

        # Get legacy json
        legacy_json = []
        try:
            legacy_json = json.loads(list_output)
        except Exception as e:
            logger.log_error(e)
            logger.log_error("Unable to parse legacy game list")
            logger.log_error("Received output:\n%s" % info_output)
            return None

        # Parse output
        purchases = []
        for entry in legacy_json:

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.get_platform())
            purchase.set_value(config.json_key_store_appid, entry.get("installer_uuid", "").strip())
            purchase.set_value(config.json_key_store_name, entry.get("game_name", "").strip())
            purchases.append(purchase)
        return purchases

    ############################################################
    # Json
    ############################################################

    # Get latest jsondata
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

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return None

        # Get script
        heirloom_script = None
        if programs.IsToolInstalled("Heirloom"):
            heirloom_script = programs.GetToolProgram("Heirloom")
        if not heirloom_script:
            logger.log_error("Heirloom was not found")
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
            logger.log_error("Unable to find legacy information for '%s'" % identifier)
            return None

        # Get legacy json
        legacy_json = {}
        try:
            legacy_json = json.loads(info_output)
        except Exception as e:
            logger.log_error(e)
            logger.log_error("Unable to parse legacy game information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.json_key_store_appid, identifier)
        json_data.set_value(config.json_key_store_name, legacy_json.get("game_name", "").strip())
        return self.augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Assets
    ############################################################

    # Get latest asset url
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
            latest_asset_url = metadataassetcollector.FindMetadataAsset(
                game_platform = self.get_platform(),
                game_name = game_name if game_name else identifier,
                asset_type = asset_type,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Video
        elif asset_type == config.AssetType.VIDEO:
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
