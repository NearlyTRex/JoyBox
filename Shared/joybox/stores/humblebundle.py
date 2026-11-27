# Imports
import types

# Local imports
from joybox import config
from joybox import logger
from joybox import fileops
from joybox import programs
from joybox import serialization
from joybox import command
from joybox import backup
from joybox import jsondata
from joybox import storebase
from joybox import strings
from joybox import paths
from joybox import settings

# HumbleBundle store
class HumbleBundle(storebase.StoreBase):

    TYPE = config.StoreType.HUMBLE_BUNDLE
    PLATFORM = config.Platform.COMPUTER_HUMBLE_BUNDLE
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_HUMBLE_BUNDLE
    KEY = config.JSON_KEY_HUMBLE
    IDENTIFIER_KEYS = types.MappingProxyType({
        config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_APPNAME,
    })

    # Constructor
    def __init__(self):
        super().__init__()

        # Get username
        self.username = settings.get_value("UserData.HumbleBundle", "humblebundle_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get email
        self.email = settings.get_value("UserData.HumbleBundle", "humblebundle_email")
        if not self.email:
            raise RuntimeError("Ini file does not have a valid email")

        # Get platform
        self.platform = settings.get_value("UserData.HumbleBundle", "humblebundle_platform")
        if not self.platform:
            raise RuntimeError("Ini file does not have a valid platform")

        # Get auth token
        self.auth_token = settings.get_value("UserData.HumbleBundle", "humblebundle_auth_token")
        if not self.auth_token:
            raise RuntimeError("Ini file does not have a valid auth token")

        # Get install dir
        self.install_dir = settings.get_path_value("UserData.HumbleBundle", "humblebundle_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # The download platform (windows, linux, mac...) from the settings, used to filter listings and builds
    def get_preferred_platform(self):
        return self.platform

    # The Humble Bundle username from the settings; the constructor refuses to build without one
    def get_user_name(self):
        return self.username

    # The Humble Bundle account email from the settings; the constructor refuses to build without one
    def get_email(self):
        return self.email

    # The _simpleauth_sess session cookie from the settings, which HumbleBundleManager signs in with
    def get_auth_token(self):
        return self.auth_token

    # Check if purchases can be imported
    def can_import_purchases(self):
        return True

    # Check if purchases can be downloaded
    def can_download_purchases(self):
        return True

    ############################################################
    # Connection
    ############################################################

    # Get how to sign in again
    def get_login_hint(self):
        return "set humblebundle_auth_token in the UserData.HumbleBundle section of JoyBox.ini to a fresh _simpleauth_sess cookie from humblebundle.com"

    ############################################################
    # Manager
    ############################################################

    # Get manager command prefix
    def get_manager_cmd(self):

        # Get script command
        script_cmd = programs.get_python_script_command("HumbleBundleManager")
        if not script_cmd:
            return None
        return script_cmd + ["--auth", self.get_auth_token()]

    # HumbleBundleManager's JSON description of one purchase as a dict; None when it gives nothing parsable
    def get_purchase_details(
        self,
        manager_cmd,
        appname,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Run info command
        info_cmd = manager_cmd + [
            "--show", appname,
            "--json",
            "--quiet"
        ]
        info_output = command.run_output_command(
            cmd = info_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not info_output:
            logger.log_error(f"Unable to describe humble purchase {appname}")
            return None

        # Get humble json
        humble_json = serialization.parse_json_or_none(info_output)
        if not isinstance(humble_json, dict):
            logger.log_error("Unable to parse humble game information for '%s'" % appname)
            logger.log_error("Received output:\n%s" % info_output)
            return None
        return humble_json

    # The purchase's display name from its details, stripped; empty when missing
    def get_purchase_name(self, humble_json):
        name = humble_json.get("human_name")
        if not isinstance(name, str):
            return ""
        return name.strip()

    # The last download timestamp for the preferred platform in the purchase details; the default build id when none
    def get_purchase_buildid(self, humble_json):
        buildid = config.DEFAULT_BUILDID
        downloads = humble_json.get("downloads")
        if not isinstance(downloads, list):
            return buildid
        for download in downloads:
            if not isinstance(download, dict) or download.get("platform") != self.get_preferred_platform():
                continue
            download_structs = download.get("download_struct")
            if not isinstance(download_structs, list):
                continue
            for download_struct in download_structs:
                if not isinstance(download_struct, dict):
                    continue
                timestamp = download_struct.get("timestamp")
                if isinstance(timestamp, bool) or not isinstance(timestamp, (int, str)) or not str(timestamp).strip():
                    continue
                buildid = str(timestamp).strip()
        return buildid

    ############################################################
    # Purchases
    ############################################################

    # Owned games for the preferred platform with a generated id, appname and name, from a cache under a day old or else HumbleBundleManager
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = self.get_purchases_cache_dir()
        cache_file_purchases = paths.join_paths(cache_dir, "humble_purchases_cache.json")

        # Load from cache if recent
        cached_purchases = self._read_purchases_cache(
            cache_file_purchases = cache_file_purchases,
            verbose = verbose)
        if cached_purchases is not None:
            return cached_purchases

        # Fetch purchases from the manager
        fetched = self._fetch_purchases(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if fetched is None:
            return None

        # Save to cache
        purchases, purchases_data = fetched
        self._write_purchases_cache(
            cache_dir = cache_dir,
            cache_file_purchases = cache_file_purchases,
            purchases_data = purchases_data,
            verbose = verbose,
            pretend_run = pretend_run)
        return purchases

    # Purchases and their cache dicts from the manager's listing and per-game details; None on any failure
    def _fetch_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get manager
        manager_cmd = self.get_manager_cmd()
        if not manager_cmd:
            return None

        # Get library listing
        list_output = self._fetch_purchase_list(
            manager_cmd = manager_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not list_output:
            return None

        # Parse output
        return self._parse_purchase_list(
            manager_cmd = manager_cmd,
            list_output = list_output,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # The manager's appname listing for the preferred platform; None (after logging) when empty
    def _fetch_purchase_list(
        self,
        manager_cmd,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get list command
        list_cmd = manager_cmd + [
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
        if not list_output:
            logger.log_error("Unable to find humble purchases")
            return None
        return list_output

    # Cached purchases when the cache is under a day old and well formed; None otherwise
    def _read_purchases_cache(self, cache_file_purchases, verbose = False):

        # Check if cache exists and is recent (less than 24 hours old)
        if not paths.does_path_exist(cache_file_purchases):
            return None
        cache_age_hours = paths.get_file_age_in_hours(cache_file_purchases)
        if cache_age_hours >= 24:
            return None
        if verbose:
            logger.log_info("Using cached Humble Bundle purchases data (%.1f hours old)" % cache_age_hours)

        # Load from cache
        cached_data = serialization.read_json_file(
            src = cache_file_purchases,
            verbose = verbose,
            exit_on_failure = False)
        if isinstance(cached_data, list) and all(isinstance(entry, dict) for entry in cached_data):
            cached_purchases = []
            for purchase_data in cached_data:
                purchase = jsondata.JsonData(
                    json_data = purchase_data,
                    json_platform = self.get_platform())
                cached_purchases.append(purchase)
            return cached_purchases
        if verbose:
            logger.log_warning("Failed to load Humble Bundle cache, will fetch fresh data")
        return None

    # Purchases and their cacheable dicts for each appname line of the listing; None when a
    # purchase cannot be described or the output names no games
    def _parse_purchase_list(
        self,
        manager_cmd,
        list_output,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        purchases = []
        purchases_data = []
        for line in list_output.split("\n"):

            # Gather info
            tokens = strings.remove_string_escape_sequences(line).split()
            if len(tokens) != 1:
                continue
            line_appname = tokens[0]

            # Get details
            humble_json = self.get_purchase_details(
                manager_cmd = manager_cmd,
                appname = line_appname,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if humble_json is None:
                return None

            # Create purchase
            purchase, purchase_data = self._create_purchase(line_appname, humble_json)
            purchases.append(purchase)
            purchases_data.append(purchase_data)

        # Output without any game names is not a library listing
        if not purchases:
            logger.log_error("Unable to find humble purchases")
            logger.log_error("Received output:\n%s" % list_output)
            return None
        return purchases, purchases_data

    # A purchase with a fresh appid, the appname and the details' name, plus the same values as a cache dict
    def _create_purchase(self, line_appname, humble_json):

        # Gather info
        line_appid = strings.generate_unique_id()
        line_name = self.get_purchase_name(humble_json)

        # Create purchase
        purchase = jsondata.JsonData(json_data = {}, json_platform = self.get_platform())
        purchase.set_value(config.JSON_KEY_STORE_APPID, line_appid)
        purchase.set_value(config.JSON_KEY_STORE_APPNAME, line_appname)
        purchase.set_value(config.JSON_KEY_STORE_NAME, line_name)

        # Store data for caching
        purchase_data = {
            config.JSON_KEY_STORE_APPID: line_appid,
            config.JSON_KEY_STORE_APPNAME: line_appname,
            config.JSON_KEY_STORE_NAME: line_name
        }
        return purchase, purchase_data

    # Write the purchases cache, logging the outcome when verbose
    def _write_purchases_cache(
        self,
        cache_dir,
        cache_file_purchases,
        purchases_data,
        verbose = False,
        pretend_run = False):
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

    ############################################################
    # Json
    ############################################################

    # Appname, name and build from HumbleBundleManager's details, with a fresh random appid each call; None when unknown
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

        # Get manager
        manager_cmd = self.get_manager_cmd()
        if not manager_cmd:
            return None

        # Get details
        humble_json = self.get_purchase_details(
            manager_cmd = manager_cmd,
            appname = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if humble_json is None:
            return None

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.JSON_KEY_STORE_APPID, strings.generate_unique_id())
        json_data.set_value(config.JSON_KEY_STORE_APPNAME, identifier)
        json_data.set_value(config.JSON_KEY_STORE_NAME, self.get_purchase_name(humble_json))
        json_data.set_value(config.JSON_KEY_STORE_BUILDID, self.get_purchase_buildid(humble_json))
        return self.augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Download
    ############################################################

    # Fetch the game for the preferred platform with HumbleBundleManager into a temp dir and archive it into output_dir
    def download(
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
        if not self.is_valid_download_identifier(identifier):
            logger.log_warning("Download identifier '%s' was not valid" % identifier)
            return False

        # Get manager
        manager_cmd = self.get_manager_cmd()
        if not manager_cmd:
            return False

        # Download and archive
        return self._download_and_archive(
            manager_cmd = manager_cmd,
            identifier = identifier,
            output_dir = output_dir,
            output_name = output_name,
            clean_output = clean_output,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Download the game into a temp dir and archive it into output_dir; True when output_dir ends up with files
    def _download_and_archive(
        self,
        manager_cmd,
        identifier,
        output_dir,
        output_name,
        clean_output,
        show_progress,
        skip_existing,
        skip_identical,
        verbose,
        pretend_run,
        exit_on_failure):

        # Download into a temporary directory and archive it
        with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir_result:
            if not tmp_dir_result:
                return False

            # Run download command
            if not self._run_download_command(manager_cmd, identifier, tmp_dir_result, verbose, pretend_run, exit_on_failure):
                return False

            # Archive downloaded files
            success = backup.archive_folder(
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

        # Check results
        return paths.does_directory_contain_files(output_dir)

    # Download the preferred platform's build into download_dir; True when the manager exits cleanly
    def _run_download_command(
        self,
        manager_cmd,
        identifier,
        download_dir,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get download command
        download_cmd = manager_cmd + [
            "--download", identifier,
            "--platform", self.get_preferred_platform(),
            "--path", download_dir,
            "--quiet"
        ]

        # Run download command
        code = command.run_returncode_command(
            cmd = download_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0
