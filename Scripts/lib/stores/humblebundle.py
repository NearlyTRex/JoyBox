# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import logger
import environment
import programs
import command
import jsondata
import storebase
import metadatacollector
import ini

# HumbleBundle store
class HumbleBundle(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get username
        self.username = ini.GetIniValue("UserData.HumbleBundle", "humblebundle_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get email
        self.email = ini.GetIniValue("UserData.HumbleBundle", "humblebundle_email")
        if not self.email:
            raise RuntimeError("Ini file does not have a valid email")

        # Get platform
        self.platform = ini.GetIniValue("UserData.HumbleBundle", "humblebundle_platform")
        if not self.platform:
            raise RuntimeError("Ini file does not have a valid platform")

        # Get auth token
        self.auth_token = ini.GetIniValue("UserData.HumbleBundle", "humblebundle_auth_token")
        if not self.auth_token:
            raise RuntimeError("Ini file does not have a valid auth token")

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.HumbleBundle", "humblebundle_install_dir")
        if not system.IsPathValid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.HUMBLE_BUNDLE.val()

    # Get type
    def GetType(self):
        return config.StoreType.HUMBLE_BUNDLE

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_HUMBLE_BUNDLE

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_HUMBLE_BUNDLE

    # Get key
    def GetKey(self):
        return config.json_key_humble

    # Get identifier keys
    def GetIdentifierKeys(self):
        return {
            config.StoreIdentifierType.INFO: config.json_key_store_appname,
            config.StoreIdentifierType.INSTALL: config.json_key_store_appname,
            config.StoreIdentifierType.LAUNCH: config.json_key_store_appname,
            config.StoreIdentifierType.DOWNLOAD: config.json_key_store_appname,
            config.StoreIdentifierType.ASSET: config.json_key_store_name,
            config.StoreIdentifierType.METADATA: config.json_key_store_name,
            config.StoreIdentifierType.PAGE: config.json_key_store_appname
        }

    # Get preferred platform
    def GetPreferredPlatform(self):
        return self.platform

    # Get user name
    def GetUserName(self):
        return self.username

    # Get email
    def GetEmail(self):
        return self.email

    # Get auth token
    def GetAuthToken(self):
        return self.auth_token

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
    # Purchases
    ############################################################

    # Get purchases
    def GetLatestPurchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = environment.GetCacheRootDir()
        cache_file_purchases = system.JoinPaths(cache_dir, "humble_purchases_cache.json")

        # Check if cache exists and is recent (less than 24 hours old)
        use_cache = False
        if system.DoesPathExist(cache_file_purchases):
            cache_age_hours = system.GetFileAgeInHours(cache_file_purchases)
            if cache_age_hours < 24:
                use_cache = True
                if verbose:
                    logger.log_info("Using cached Humble Bundle purchases data (%.1f hours old)" % cache_age_hours)

        # Load from cache if available
        if use_cache:
            cached_data = system.ReadJsonFile(
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
                    logger.log_warning("Failed to load Humble Bundle cache, will fetch fresh data")
                use_cache = False

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return False

        # Get script
        humble_script = None
        if programs.IsToolInstalled("HumbleBundleManager"):
            humble_script = programs.GetToolProgram("HumbleBundleManager")
        if not humble_script:
            logger.log_error("HumbleBundleManager was not found")
            return False

        # Get list command
        list_cmd = [
            python_tool,
            humble_script,
            "--auth", self.GetAuthToken(),
            "--list",
            "--platform", self.GetPreferredPlatform(),
            "--quiet"
        ]

        # Run list command
        list_output = command.RunOutputCommand(
            cmd = list_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(list_output) == 0:
            logger.log_error("Unable to find humble purchases")
            return None

        # Parse output
        purchases = []
        purchases_data = []
        for line in list_output.split("\n"):

            # Gather info
            line = system.RemoveStringEscapeSequences(line)
            tokens = line.split(" ")
            if len(tokens) != 1:
                continue
            line_appname = tokens[0].strip()

            # Get info command
            info_cmd = [
                python_tool,
                humble_script,
                "--show", line_appname,
                "--json",
                "--quiet"
            ]

            # Run info command
            info_output = command.RunOutputCommand(
                cmd = info_cmd,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if len(info_output) == 0:
                logger.log_error(f"Unable to describe humble purchase {line_appname}")
                return None

            # Get humble json
            humble_json = {}
            try:
                humble_json = json.loads(info_output)
            except Exception as e:
                logger.log_error(e)
                logger.log_error("Unable to parse humble game information for '%s'" % line_appname)
                logger.log_error("Received output:\n%s" % info_output)
                return None

            # Gather info
            line_appid = system.GenerateUniqueID()
            line_name = humble_json.get("human_name", "")

            # Create purchase
            purchase = jsondata.JsonData(json_data = {}, json_platform = self.GetPlatform())
            purchase.set_value(config.json_key_store_appid, line_appid)
            purchase.set_value(config.json_key_store_appname, line_appname)
            purchase.set_value(config.json_key_store_name, line_name)
            purchases.append(purchase)

            # Store data for caching
            purchases_data.append({
                config.json_key_store_appid: line_appid,
                config.json_key_store_appname: line_appname,
                config.json_key_store_name: line_name
            })

        # Save to cache
        system.MakeDirectory(cache_dir, verbose = verbose, pretend_run = pretend_run)
        success = system.WriteJsonFile(
            src = cache_file_purchases,
            json_data = purchases_data,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if success and verbose:
            logger.log_info("Saved Humble Bundle purchases data to cache")
        elif not success and verbose:
            logger.log_warning("Failed to save Humble Bundle cache")
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
            return False

        # Get script
        humble_script = None
        if programs.IsToolInstalled("HumbleBundleManager"):
            humble_script = programs.GetToolProgram("HumbleBundleManager")
        if not humble_script:
            logger.log_error("HumbleBundleManager was not found")
            return False

        # Get info command
        info_cmd = [
            python_tool,
            humble_script,
            "--auth", self.GetAuthToken(),
            "--show", identifier,
            "--json",
            "--quiet"
        ]

        # Run info command
        info_output = command.RunOutputCommand(
            cmd = info_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0:
            logger.log_error(f"Unable to describe humble purchase {identifier}")
            return None

        # Get humble json
        humble_json = {}
        try:
            humble_json = json.loads(info_output)
        except Exception as e:
            logger.log_error(e)
            logger.log_error("Unable to parse humble game information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None

        # Build jsondata
        json_data = self.CreateDefaultJsondata()
        json_data.set_value(config.json_key_store_appid, system.GenerateUniqueID())
        json_data.set_value(config.json_key_store_appname, identifier)
        json_data.set_value(config.json_key_store_name, humble_json.get("human_name"))
        for download in humble_json.get("downloads", []):
            if download.get("platform") == self.GetPreferredPlatform():
                for download_struct in download.get("download_struct", []):
                    json_data.set_value(config.json_key_store_buildid, str(download_struct.get("timestamp", config.default_buildid)))
        return self.AugmentJsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
