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

# Amazon store
class Amazon(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Amazon", "amazon_install_dir")
        if not system.IsPathValid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.AMAZON.val()

    # Get type
    def GetType(self):
        return config.StoreType.AMAZON

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_AMAZON_GAMES

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_AMAZON_GAMES

    # Get key
    def GetKey(self):
        return config.json_key_amazon

    # Get identifier keys
    def GetIdentifierKeys(self):
        return {
            config.StoreIdentifierType.INFO: config.json_key_store_appid,
            config.StoreIdentifierType.INSTALL: config.json_key_store_appid,
            config.StoreIdentifierType.LAUNCH: config.json_key_store_appid,
            config.StoreIdentifierType.DOWNLOAD: config.json_key_store_appid,
            config.StoreIdentifierType.ASSET: config.json_key_store_appid,
            config.StoreIdentifierType.METADATA: config.json_key_store_name,
            config.StoreIdentifierType.PAGE: config.json_key_store_appid
        }

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
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            system.LogError("Nile was not found")
            return False

        # Get login command
        login_cmd = [
            python_tool,
            nile_script,
            "--quiet",
            "auth",
            "--login"
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
            nile_script,
            "--quiet",
            "auth",
            "--refresh"
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

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return None

        # Get script
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            system.LogError("Nile was not found")
            return None

        # Get refresh command
        refresh_cmd = [
            python_tool,
            nile_script,
            "--quiet",
            "auth",
            "--refresh"
        ]

        # Run refresh command
        code = command.RunReturncodeCommand(
            cmd = refresh_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if (code != 0):
            return None

        # Get sync command
        sync_cmd = [
            python_tool,
            nile_script,
            "--quiet",
            "library",
            "sync"
        ]

        # Run sync command
        code = command.RunReturncodeCommand(
            cmd = sync_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if (code != 0):
            return None

        # Get list command
        list_cmd = [
            python_tool,
            nile_script,
            "library",
            "list"
        ]

        # Run list command
        list_output = command.RunOutputCommand(
            cmd = list_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(list_output) == 0:
            system.LogError("Unable to find amazon purchases")
            return None

        # Parse output
        purchases = []
        for line in list_output.split("\n"):

            # Gather info
            line = system.RemoveStringEscapeSequences(line)
            line = line.replace("(INSTALLED) ", "")
            tokens = line.split(" GENRES: ")
            if len(tokens) != 2:
                continue
            line = tokens[0]
            tokens = line.split(" ID: ")
            if len(tokens) != 2:
                continue
            line_title = tokens[0].strip()
            line_appid = tokens[1].strip()

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.GetPlatform())
            purchase.set_value(config.json_key_store_appid, line_appid)
            purchase.set_value(config.json_key_store_name, line_title)
            purchases.append(purchase)
        return purchases

    ############################################################
    # Json
    ############################################################

    # Get jsondata
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
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            system.LogError("Nile was not found")
            return None

        # Get info command
        info_cmd = [
            python_tool,
            nile_script,
            "--quiet",
            "details",
            identifier
        ]

        # Run info command
        info_output = command.RunOutputCommand(
            cmd = info_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0:
            system.LogError("Unable to find amazon information for '%s'" % identifier)
            return None

        # Get amazon json
        amazon_json = {}
        try:
            amazon_json = json.loads(info_output)
        except Exception as e:
            system.LogError(e)
            system.LogError("Unable to parse amazon information for '%s'" % identifier)
            system.LogError("Received output:\n%s" % info_output)
            return None

        # Build jsondata
        json_data = jsondata.JsonData({}, self.GetPlatform())
        json_data.set_value(config.json_key_store_appid, identifier)
        json_data.set_value(config.json_key_store_buildid, "")

        # Augment by json
        if "version" in amazon_json:
            json_data.set_value(config.json_key_store_buildid, str(amazon_json["version"]))
        if "product" in amazon_json:
            appdata = amazon_json["product"]
            if "title" in appdata:
                json_data.set_value(config.json_key_store_name, str(appdata["title"]))

        # Return jsondata
        return json_data

    ############################################################
    # Download
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

        # Check identifier
        if not self.IsValidDownloadIdentifier(identifier):
            system.LogWarning("Download identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return False

        # Get script
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            system.LogError("Nile was not found")
            return False

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
            verbose = verbose,
            pretend_run = pretend_run)
        if not tmp_dir_success:
            return False

        # Get download command
        download_cmd = [
            python_tool,
            nile_script,
            "verify",
            "--path", tmp_dir_result,
            identifier
        ]

        # Run download command
        code = command.RunReturncodeCommand(
            cmd = download_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Archive downloaded files
        success = self.Archive(
            source_dir = tmp_dir_result,
            output_dir = output_dir,
            output_name = output_name,
            clean_output = clean_output,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Delete temporary directory
        system.RemoveDirectory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check results
        return system.DoesDirectoryContainFiles(output_dir)

    ############################################################
