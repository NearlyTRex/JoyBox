# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import logger
import paths
import environment
import fileops
import command
import backup
import programs
import serialization
import jsondata
import storebase
import strings
import ini

# Amazon store
class Amazon(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Amazon", "amazon_install_dir")
        if not paths.is_path_valid(self.install_dir):
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
            config.StoreIdentifierType.ASSET: config.json_key_store_name,
            config.StoreIdentifierType.METADATA: config.json_key_store_name,
            config.StoreIdentifierType.PAGE: config.json_key_store_name
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

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return False

        # Get script
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            logger.log_error("Nile was not found")
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

        # Get cache file path
        cache_dir = environment.get_cache_root_dir()
        cache_file_purchases = paths.join_paths(cache_dir, "amazon_purchases_cache.json")

        # Check if cache exists and is recent (less than 24 hours old)
        use_cache = False
        if paths.does_path_exist(cache_file_purchases):
            cache_age_hours = paths.get_file_age_in_hours(cache_file_purchases)
            if cache_age_hours < 24:
                use_cache = True
                if verbose:
                    logger.log_info("Using cached Amazon purchases data (%.1f hours old)" % cache_age_hours)

        # Load from cache if available
        if use_cache:
            cached_data = serialization.read_json_file(
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
                    logger.log_warning("Failed to load Amazon cache, will fetch fresh data")
                use_cache = False

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return None

        # Get script
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            logger.log_error("Nile was not found")
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
            logger.log_error("Unable to find amazon purchases")
            return None

        # Parse output
        purchases = []
        purchases_data = []
        for line in list_output.split("\n"):

            # Gather info
            line = strings.remove_string_escape_sequences(line)
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

            # Store data for caching
            purchases_data.append({
                config.json_key_store_appid: line_appid,
                config.json_key_store_name: line_title
            })

        # Save to cache
        fileops.make_directory(cache_dir, verbose = verbose, pretend_run = pretend_run)
        success = serialization.write_json_file(
            src = cache_file_purchases,
            json_data = purchases_data,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if success and verbose:
            logger.log_info("Saved Amazon purchases data to cache")
        elif not success and verbose:
            logger.log_warning("Failed to save Amazon cache")
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
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            logger.log_error("Nile was not found")
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
            logger.log_error("Unable to find amazon information for '%s'" % identifier)
            return None

        # Get amazon json
        amazon_json = {}
        try:
            amazon_json = json.loads(info_output)
        except Exception as e:
            logger.log_error(e)
            logger.log_error("Unable to parse amazon information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None

        # Build jsondata
        json_data = self.CreateDefaultJsondata()
        json_data.set_value(config.json_key_store_appid, identifier)
        json_data.set_value(config.json_key_store_buildid, amazon_json.get("version", config.default_buildid).strip())
        json_data.set_value(config.json_key_store_name, amazon_json.get("product", {}).get("title", "").strip())
        return self.AugmentJsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Download
    ############################################################

    # Download
    def Download(
        self,
        identifier,
        output_dir,
        output_name = None,
        branch = None,
        clean_output = False,
        show_progress = False,
        skip_existing = False,
        skip_identical = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidDownloadIdentifier(identifier):
            logger.log_warning("Download identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return False

        # Get script
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            logger.log_error("Nile was not found")
            return False

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
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
        success = backup.ArchiveFolder(
            input_path = tmp_dir_result,
            output_path = output_dir,
            output_name = output_name,
            clean_output = clean_output,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Delete temporary directory
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check results
        return paths.does_directory_contain_files(output_dir)

    ############################################################
