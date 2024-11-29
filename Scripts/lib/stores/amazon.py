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
import hashing
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

    # Get name
    def GetName(self):
        return "Amazon"

    # Get type
    def GetType(self):
        return config.store_type_amazon

    # Get platform
    def GetPlatform(self):
        return config.platform_computer_amazon_games

    # Get category
    def GetCategory(self):
        return config.game_category_computer

    # Get subcategory
    def GetSubcategory(self):
        return config.game_subcategory_amazon_games

    # Get key
    def GetKey(self):
        return config.json_key_amazon

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.store_identifier_type_metadata:
            return json_wrapper.get_value(config.json_key_store_name)
        return json_wrapper.get_value(config.json_key_store_appid)

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

        # Make temporary dirs
        tmp_dir_fetch = os.path.join(tmp_dir_result, "fetch")
        tmp_dir_archive = os.path.join(tmp_dir_result, "archive")
        system.MakeDirectory(
            dir = tmp_dir_fetch,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        system.MakeDirectory(
            dir = tmp_dir_archive,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Get fetch command
        fetch_cmd = [
            python_tool,
            nile_script,
            "verify",
            "--path", tmp_dir_fetch,
            identifier
        ]

        # Run fetch command
        code = command.RunBlockingCommand(
            cmd = fetch_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            system.LogError("Encountered error fetching")
            return False

        # Check that files downloaded
        if system.IsDirectoryEmpty(tmp_dir_fetch):
            system.LogError("Files were not downloaded successfully")
            return False

        # Archive downloaded files
        success = archive.CreateArchiveFromFolder(
            archive_file = os.path.join(tmp_dir_archive, "%s.7z" % output_name),
            source_dir = tmp_dir_fetch,
            volume_size = "4092m",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.RemoveDirectory(
                dir = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return False

        # Clean output
        if clean_output:
            system.RemoveDirectoryContents(
                dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Move archived files
        success = system.MoveContents(
            src = tmp_dir_archive,
            dest = output_dir,
            show_progress = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.RemoveDirectory(
                dir = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return False

        # Delete temporary directory
        system.RemoveDirectory(
            dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check result
        return os.path.exists(output_dir)

    ############################################################
