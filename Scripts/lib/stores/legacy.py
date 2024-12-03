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
        return "Legacy"

    # Get type
    def GetType(self):
        return config.store_type_legacy

    # Get platform
    def GetPlatform(self):
        return config.platform_computer_legacy_games

    # Get category
    def GetCategory(self):
        return config.game_category_computer

    # Get subcategory
    def GetSubcategory(self):
        return config.game_subcategory_legacy_games

    # Get key
    def GetKey(self):
        return config.json_key_legacy

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.store_identifier_type_metadata:
            return json_wrapper.get_value(config.json_key_store_appurl)
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
                purchase.set_value(config.json_key_store_appid, entry["installer_uuid"])
            if "game_name" in entry:
                purchase.set_value(config.json_key_store_name, entry["game_name"].strip())
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
            game_info[config.json_key_store_name] = legacy_json["game_name"].strip()

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
        return None

    ############################################################

    # Get latest url
    def GetLatestUrl(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Ask them which one they want to use
        return system.PromptForUrl("Which url do you want to use? [Enter a valid url]")

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
