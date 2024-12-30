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

# Fix game title
def FixGameTitle(title):
    if title.endswith(" CE"):
        title = title.replace(" CE", " Collector's Edition")
    return title

# Legacy store
class Legacy(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get user details
        self.username = ini.GetIniValue("UserData.Legacy", "legacy_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid legacy user details")

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Legacy", "legacy_install_dir")
        if not system.IsPathValid(self.install_dir) or not system.DoesPathExist(self.install_dir):
            raise RuntimeError("Ini file does not have a valid legacy install dir")

    # Get name
    def GetName(self):
        return config.StoreType.LEGACY.value

    # Get type
    def GetType(self):
        return config.StoreType.LEGACY

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_LEGACY_GAMES

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_LEGACY_GAMES

    # Get key
    def GetKey(self):
        return config.json_key_legacy

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.StoreIdentifierType.METADATA:
            return json_wrapper.get_value(config.json_key_store_name)
        return json_wrapper.get_value(config.json_key_store_appid)

    # Get user name
    def GetUserName(self):
        return self.username

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    ############################################################

    # Login
    def Login(
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
        return (code == 0)

    ############################################################

    # Get purchases
    def GetPurchases(
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
                purchase.set_value(config.json_key_store_name, FixGameTitle(entry["game_name"]).strip())
            purchases.append(purchase)
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

        # Check identifier
        if not self.IsValidIdentifier(identifier):
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

        # Build game info
        game_info = {}
        game_info[config.json_key_store_appid] = identifier

        # Augment by json
        if "game_name" in legacy_json:
            game_info[config.json_key_store_name] = FixGameTitle(legacy_json["game_name"]).strip()

        # Return game info
        return jsondata.JsonData(game_info, self.GetPlatform())

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

        # Collect metadata entry
        return metadatacollector.CollectMetadataFromAll(
            game_platform = self.GetPlatform(),
            game_name = identifier,
            keys_to_check = config.metadata_keys_downloadable,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################

    # Get latest url
    def GetLatestUrl(
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
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Get keywords name
        keywords_name = system.EncodeUrlString(FixGameTitle(identifier).strip(), use_plus = True)

        # Load url
        success = webpage.LoadUrl(web_driver, "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=" + keywords_name)
        if not success:
            return None

        # Look for game description
        element_game_description = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "productFullDetail__descriptionContent"}),
            verbose = verbose)
        if not element_game_description:
            return None

        # Get current url
        appurl = system.StripStringQueryParams(webpage.GetCurrentPageUrl(web_driver))

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
