# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import logger
import environment
import fileops
import programs
import serialization
import command
import jsondata
import storebase
import strings
import metadatacollector
import paths
import ini

# HumbleBundle store
class HumbleBundle(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get username
        self.username = ini.get_ini_value("UserData.HumbleBundle", "humblebundle_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get email
        self.email = ini.get_ini_value("UserData.HumbleBundle", "humblebundle_email")
        if not self.email:
            raise RuntimeError("Ini file does not have a valid email")

        # Get platform
        self.platform = ini.get_ini_value("UserData.HumbleBundle", "humblebundle_platform")
        if not self.platform:
            raise RuntimeError("Ini file does not have a valid platform")

        # Get auth token
        self.auth_token = ini.get_ini_value("UserData.HumbleBundle", "humblebundle_auth_token")
        if not self.auth_token:
            raise RuntimeError("Ini file does not have a valid auth token")

        # Get install dir
        self.install_dir = ini.get_ini_path_value("UserData.HumbleBundle", "humblebundle_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def get_name(self):
        return config.StoreType.HUMBLE_BUNDLE.val()

    # Get type
    def get_type(self):
        return config.StoreType.HUMBLE_BUNDLE

    # Get platform
    def get_platform(self):
        return config.Platform.COMPUTER_HUMBLE_BUNDLE

    # Get supercategory
    def get_supercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def get_category(self):
        return config.Category.COMPUTER

    # Get subcategory
    def get_subcategory(self):
        return config.Subcategory.COMPUTER_HUMBLE_BUNDLE

    # Get key
    def get_key(self):
        return config.json_key_humble

    # Get identifier keys
    def get_identifier_keys(self):
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
    def get_preferred_platform(self):
        return self.platform

    # Get user name
    def get_user_name(self):
        return self.username

    # Get email
    def get_email(self):
        return self.email

    # Get auth token
    def GetAuthToken(self):
        return self.auth_token

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
    # Purchases
    ############################################################

    # Get purchases
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = environment.get_cache_root_dir()
        cache_file_purchases = paths.join_paths(cache_dir, "humble_purchases_cache.json")

        # Check if cache exists and is recent (less than 24 hours old)
        use_cache = False
        if paths.does_path_exist(cache_file_purchases):
            cache_age_hours = paths.get_file_age_in_hours(cache_file_purchases)
            if cache_age_hours < 24:
                use_cache = True
                if verbose:
                    logger.log_info("Using cached Humble Bundle purchases data (%.1f hours old)" % cache_age_hours)

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
                        json_platform = self.get_platform())
                    cached_purchases.append(purchase)
                return cached_purchases
            else:
                if verbose:
                    logger.log_warning("Failed to load Humble Bundle cache, will fetch fresh data")
                use_cache = False

        # Get tool
        python_tool = None
        if programs.is_tool_installed("PythonVenvPython"):
            python_tool = programs.get_tool_program("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return False

        # Get script
        humble_script = None
        if programs.is_tool_installed("HumbleBundleManager"):
            humble_script = programs.get_tool_program("HumbleBundleManager")
        if not humble_script:
            logger.log_error("HumbleBundleManager was not found")
            return False

        # Get list command
        list_cmd = [
            python_tool,
            humble_script,
            "--auth", self.GetAuthToken(),
            "--list",
            "--platform", self.get_preferred_platform(),
            "--quiet"
        ]

        # Run list command
        list_output = command.run_output_command(
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
            line = strings.remove_string_escape_sequences(line)
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
            info_output = command.run_output_command(
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
            line_appid = strings.generate_unique_id()
            line_name = humble_json.get("human_name", "")

            # Create purchase
            purchase = jsondata.JsonData(json_data = {}, json_platform = self.get_platform())
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
        fileops.make_directory(cache_dir, verbose = verbose, pretend_run = pretend_run)
        success = serialization.write_json_file(
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
        if programs.is_tool_installed("PythonVenvPython"):
            python_tool = programs.get_tool_program("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return False

        # Get script
        humble_script = None
        if programs.is_tool_installed("HumbleBundleManager"):
            humble_script = programs.get_tool_program("HumbleBundleManager")
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
        info_output = command.run_output_command(
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
        json_data = self.create_default_jsondata()
        json_data.set_value(config.json_key_store_appid, strings.generate_unique_id())
        json_data.set_value(config.json_key_store_appname, identifier)
        json_data.set_value(config.json_key_store_name, humble_json.get("human_name"))
        for download in humble_json.get("downloads", []):
            if download.get("platform") == self.get_preferred_platform():
                for download_struct in download.get("download_struct", []):
                    json_data.set_value(config.json_key_store_buildid, str(download_struct.get("timestamp", config.default_buildid)))
        return self.augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
