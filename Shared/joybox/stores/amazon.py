# Imports
import types
import os
import re

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import command
from joybox import programs
from joybox import serialization
from joybox import jsondata
from joybox import storebase
from joybox import strings

# Nile library list line: optional installed marker, title, id, optional genres
nile_library_line = re.compile(r"^(?:\(INSTALLED\) )?(?P<title>.*) ID: (?P<appid>\S+)(?: GENRES: .*)?$")

# Amazon store
class Amazon(storebase.StoreBase):

    TYPE = config.StoreType.AMAZON
    PLATFORM = config.Platform.COMPUTER_AMAZON_GAMES
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_AMAZON_GAMES
    KEY = config.JSON_KEY_AMAZON
    IDENTIFIER_KEYS = types.MappingProxyType({
        config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_NAME,
        config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_NAME,
    })

    # Constructor
    def __init__(self):
        super().__init__()

        # Get install dir
        self.load_install_dir("UserData.Amazon", "amazon_install_dir")

    ############################################################
    # Store
    ############################################################

    # Check if purchases can be imported
    def can_import_purchases(self):
        return True

    # Check if purchases can be downloaded
    def can_download_purchases(self):
        return True

    ############################################################
    # Connection
    ############################################################

    # Get files the purchase listing's saved sign-in is kept in
    def get_login_files(self):
        config_dir = paths.join_paths(os.environ.get("NILE_CONFIG_PATH") or self.get_user_config_dir(), "nile")
        return [paths.join_paths(config_dir, "user.json")]

    # Sign in through Nile interactively, then refresh its token; True at once when already signed in
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Get script command
        script_cmd = programs.get_python_script_command("Nile")
        if not script_cmd:
            return False

        # Log in, then refresh the token
        for auth_flag in ("--login", "--refresh"):
            code = self._run_interactive_auth(
                script_cmd = script_cmd,
                auth_flag = auth_flag,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if code != 0:
                return False

        # Should be successful
        self.set_logged_in(True)
        return True

    # Run one interactive Nile auth step (--login or --refresh); returns its exit code
    def _run_interactive_auth(
        self,
        script_cmd,
        auth_flag,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get auth command
        auth_cmd = script_cmd + [
                        "--quiet",
            "auth",
            auth_flag
        ]

        # Run auth command
        return command.run_interactive_command(
            cmd = auth_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Purchases
    ############################################################

    # Owned titles as appid/name entries, from a cache under a day old or else a Nile sync and library list
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = self.get_purchases_cache_dir()
        cache_file_purchases = paths.join_paths(cache_dir, "amazon_purchases_cache.json")

        # Load from cache if recent
        cached_data = self.read_purchases_cache(cache_file_purchases, "Amazon", verbose = verbose)
        if cached_data is not None:
            return self.make_purchases(cached_data)

        # Get library list
        list_output = self._fetch_library_list(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not list_output:
            return None

        # Parse output and save to cache
        purchases, purchases_data = self._parse_library_list(list_output)
        self.write_purchases_cache(
            cache_dir = cache_dir,
            cache_file = cache_file_purchases,
            purchases_data = purchases_data,
            store_label = "Amazon",
            verbose = verbose,
            pretend_run = pretend_run)
        return purchases

    # Nile's library list output after a token refresh and library sync; None on any failure
    def _fetch_library_list(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get script command
        script_cmd = programs.get_python_script_command("Nile")
        if not script_cmd:
            return None

        # Refresh the token and sync the library
        for nile_args in (["auth", "--refresh"], ["library", "sync"]):
            code = command.run_returncode_command(
                cmd = script_cmd + ["--quiet"] + nile_args,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if code != 0:
                return None

        # Get list command
        list_cmd = script_cmd + [
                        "library",
            "list"
        ]

        # Run list command
        list_output = command.run_output_command(
            cmd = list_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(list_output) == 0:
            logger.log_error("Unable to find amazon purchases")
            return None
        return list_output

    # Purchases and their cacheable appid/name dicts from Nile's library list output
    def _parse_library_list(self, list_output):
        purchases = []
        purchases_data = []
        for line in list_output.split("\n"):

            # Gather info
            line = strings.remove_string_escape_sequences(line).strip()
            match = nile_library_line.match(line)
            if not match:
                continue
            line_title = match.group("title").strip()
            line_appid = match.group("appid").strip()

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.get_platform())
            purchase.set_value(config.JSON_KEY_STORE_APPID, line_appid)
            purchase.set_value(config.JSON_KEY_STORE_NAME, line_title)
            purchases.append(purchase)

            # Store data for caching
            purchases_data.append({
                config.JSON_KEY_STORE_APPID: line_appid,
                config.JSON_KEY_STORE_NAME: line_title
            })
        return purchases, purchases_data

    ############################################################
    # Json
    ############################################################

    # Appid, version and title from Nile's details output; None when Nile gives nothing usable
    def fetch_latest_jsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get script command
        del branch
        script_cmd = programs.get_python_script_command("Nile")
        if not script_cmd:
            return None

        # Get amazon json
        amazon_json = self._fetch_details_json(
            script_cmd = script_cmd,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if amazon_json is None:
            return None

        # Build jsondata
        return self._build_details_jsondata(identifier, amazon_json)

    # Default store json filled with the appid, version (default build id when blank) and title from Nile's details
    def _build_details_jsondata(self, identifier, amazon_json):

        # Get details
        amazon_version = amazon_json.get("version")
        if not isinstance(amazon_version, str) or not amazon_version.strip():
            amazon_version = config.DEFAULT_BUILDID
        amazon_product = amazon_json.get("product")
        if not isinstance(amazon_product, dict):
            amazon_product = {}
        amazon_title = amazon_product.get("title")
        if not isinstance(amazon_title, str):
            amazon_title = ""

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.JSON_KEY_STORE_APPID, identifier)
        json_data.set_value(config.JSON_KEY_STORE_BUILDID, amazon_version.strip())
        json_data.set_value(config.JSON_KEY_STORE_NAME, amazon_title.strip())
        return json_data

    # Nile's details output for the game as a dict; None (after logging) when empty or unparsable
    def _fetch_details_json(
        self,
        script_cmd,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get info command
        info_cmd = script_cmd + [
                        "--quiet",
            "details",
            identifier
        ]

        # Run info command
        info_output = command.run_output_command(
            cmd = info_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0:
            logger.log_error("Unable to find amazon information for '%s'" % identifier)
            return None

        # Get amazon json
        amazon_json = serialization.parse_json_or_none(info_output)
        if not isinstance(amazon_json, dict):
            logger.log_error("Unable to parse amazon information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None
        return amazon_json

    ############################################################
    # Download
    ############################################################

    # Nile's command prefix, the tool download fetches games with; None when Nile is missing
    def get_download_tool_cmd(self):
        return programs.get_python_script_command("Nile")

    # Nile's verify command line, which fetches the game into download_dir
    def build_download_cmd(self, tool_cmd, identifier, download_dir):

        # Get download command
        return tool_cmd + [
                            "verify",
            "--path", download_dir,
            identifier
        ]

    ############################################################
