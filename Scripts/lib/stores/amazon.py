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

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    ############################################################
    # Identifiers
    ############################################################

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.StoreIdentifierType.METADATA:
            return json_wrapper.get_value(config.json_key_store_name)
        return json_wrapper.get_value(config.json_key_store_appid)

    ############################################################
    # Connection
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
        code = command.RunBlockingCommand(
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
        code = command.RunBlockingCommand(
            cmd = refresh_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    ############################################################
    # Purchases
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
        code = command.RunBlockingCommand(
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
        code = command.RunBlockingCommand(
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

        # Build game info
        game_info = {}
        game_info[config.json_key_store_appid] = identifier
        game_info[config.json_key_store_buildid] = ""

        # Augment by json
        if "version" in amazon_json:
            game_info[config.json_key_store_buildid] = str(amazon_json["version"])
        if "product" in amazon_json:
            appdata = amazon_json["product"]
            if "title" in appdata:
                game_info[config.json_key_store_name] = str(appdata["title"])

        # Return game info
        return jsondata.JsonData(game_info, self.GetPlatform())

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
        code = command.RunBlockingCommand(
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
            dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check results
        return system.DoesDirectoryContainFiles(output_dir)

    ############################################################
