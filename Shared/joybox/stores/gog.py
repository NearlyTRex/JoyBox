# Imports
import types
import os

# Local imports
from joybox import config
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import serialization
from joybox import logger
from joybox import fileops
from joybox import filebulk
from joybox import network
from joybox import paths
from joybox import settings
from joybox import jsondata
from joybox import webpage
from joybox import webfetch
from joybox import storebase
from joybox import strings
from joybox import metadataentry
from joybox import metadataassetcollector
from joybox import manifest

# GOG platform names as gogdl spells them
gogdl_platforms = {
    "mac": "osx"
}

# Set developer/publisher, release date or genre from one "details__row" text on the game page
def _read_detail_row(element_detail_text, metadata_entry):

    # Developer/Publisher
    if strings.does_string_start_with_substring(element_detail_text, "Company:"):
        company_text = strings.trim_substring_from_start(element_detail_text, "Company:").strip()
        company_parts = company_text.split("/")
        metadata_entry.set_developer(company_parts[0].strip())
        if len(company_parts) > 1:
            metadata_entry.set_publisher(company_parts[1].strip())

    # Release
    elif strings.does_string_start_with_substring(element_detail_text, "Release date:"):
        release_text = strings.trim_substring_from_start(element_detail_text, "Release date:").strip()
        release_text = strings.convert_date_string(release_text, "%B %d, %Y", "%Y-%m-%d")
        if release_text:
            metadata_entry.set_release(release_text)

    # Genre
    elif strings.does_string_start_with_substring(element_detail_text, "Genre:"):
        genre_text = strings.trim_substring_from_start(element_detail_text, "Genre:").strip().replace(" - ", ";")
        metadata_entry.set_genre(genre_text)

# HeroicGogDL's program and auth json paths; Nones, logged, when either is missing
def find_gogdl_script():
    gogdl_script = None
    auth_json = None
    if programs.is_tool_installed("HeroicGogDL"):
        gogdl_script = programs.get_tool_program("HeroicGogDL")
        auth_json = programs.get_tool_path_config_value("HeroicGogDL", "auth_json")
    if not gogdl_script or not auth_json:
        logger.log_error("HeroicGogDL was not found")
        return None, None
    return gogdl_script, auth_json

# Move dlc/extra into the download's extra folder, keeping files already there
def _merge_dlc_extras(download_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    tmp_dir_extra = paths.join_paths(download_dir, "extra")
    tmp_dir_dlc = paths.join_paths(download_dir, "dlc")
    tmp_dir_dlc_extra = paths.join_paths(tmp_dir_dlc, "extra")
    if paths.does_directory_contain_files(tmp_dir_dlc_extra):
        filebulk.move_contents(
            src = tmp_dir_dlc_extra,
            dest = tmp_dir_extra,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        fileops.remove_directory(
            src = tmp_dir_dlc_extra,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Move the downloaded files into output_dir, emptying it first when clean_output is set
def _move_to_output(
    download_dir, output_dir,
    clean_output = False, show_progress = False, skip_existing = False, skip_identical = False,
    verbose = False, pretend_run = False, exit_on_failure = False):

    # Clean output
    if clean_output:
        fileops.remove_directory_contents(
            src = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Move downloaded files
    return filebulk.move_contents(
        src = download_dir,
        dest = output_dir,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# GOG store
class GOG(storebase.StoreBase):

    TYPE = config.StoreType.GOG
    PLATFORM = config.Platform.COMPUTER_GOG
    SUPERCATEGORY = config.Supercategory.ROMS
    CATEGORY = config.Category.COMPUTER
    SUBCATEGORY = config.Subcategory.COMPUTER_GOG
    KEY = config.JSON_KEY_GOG
    IDENTIFIER_KEYS = types.MappingProxyType({
        config.StoreIdentifierType.INFO: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.INSTALL: config.JSON_KEY_STORE_APPID,
        config.StoreIdentifierType.LAUNCH: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.DOWNLOAD: config.JSON_KEY_STORE_APPNAME,
        config.StoreIdentifierType.ASSET: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.METADATA: config.JSON_KEY_STORE_APPURL,
        config.StoreIdentifierType.PAGE: config.JSON_KEY_STORE_APPNAME,
    })

    # Constructor
    def __init__(self):
        super().__init__()

        # Get username
        self.username = settings.get_value("UserData.GOG", "gog_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get email
        self.email = settings.get_value("UserData.GOG", "gog_email")
        if not self.email:
            raise RuntimeError("Ini file does not have a valid email")

        # Get platform
        self.platform = settings.get_value("UserData.GOG", "gog_platform")
        if not self.platform:
            raise RuntimeError("Ini file does not have a valid platform")

        # Get includes
        self.includes = settings.get_value("UserData.GOG", "gog_includes")

        # Get excludes
        self.excludes = settings.get_value("UserData.GOG", "gog_excludes")

        # Get install dir
        self.install_dir = settings.get_path_value("UserData.GOG", "gog_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # The GOG installer OS (windows, linux, mac) from the settings, used to pick builds and downloads
    def get_preferred_platform(self):
        return self.platform

    # The GOG username from the settings; the constructor refuses to build without one
    def get_user_name(self):
        return self.username

    # The GOG account email from the settings; the constructor refuses to build without one
    def get_email(self):
        return self.email

    # Check if store can handle installing
    def can_handle_installing(self):
        return True

    # Check if store can handle launching
    def can_handle_launching(self):
        return False

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
        if not programs.is_tool_installed("LGOGDownloader"):
            return []
        config_dir = self.get_user_config_dir()
        appimage_home_dir = os.path.realpath(programs.get_tool_program("LGOGDownloader") + ".home")
        if paths.is_path_directory(appimage_home_dir):
            config_dir = paths.join_paths(appimage_home_dir, ".config")
        return [paths.join_paths(config_dir, "lgogdownloader", "galaxy_tokens.json")]

    # Login LGOGDownloader
    def login_lgog_downloader(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        gog_tool = programs.find_tool_program("LGOGDownloader")
        if not gog_tool:
            return False

        # Get login command
        login_cmd = [
            gog_tool,
            "--login"
        ]

        # Run login command
        code = command.run_interactive_command(
            cmd = login_cmd,
            options = commandbase.create_command_options(
                blocking_processes = [gog_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0

    # Login HeroicGogDL
    def login_heroic_gogdl(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        python_tool = programs.find_tool_program("PythonVenvPython")
        if not python_tool:
            return False

        # Get script
        login_script = None
        auth_json = None
        if programs.is_tool_installed("HeroicGogDL"):
            login_script = programs.get_tool_path_config_value("HeroicGogDL", "login_script")
            auth_json = programs.get_tool_path_config_value("HeroicGogDL", "auth_json")
        if not login_script or not auth_json:
            logger.log_error("HeroicGogDL was not found")
            return False

        # Get login command
        login_cmd = [
            python_tool,
            login_script,
            auth_json
        ]

        # Run login command
        code = command.run_interactive_command(
            cmd = login_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0

    # Sign in to both LGOGDownloader and HeroicGogDL interactively; True only when both succeed
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Login LGOGDownloader
        success = self.login_lgog_downloader(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Login HeroicGogDL
        success = self.login_heroic_gogdl(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Should be successful
        self.set_logged_in(True)
        return True

    ############################################################
    # Page
    ############################################################

    # The gog.com game page for a slug, built from the identifier without checking it exists
    def get_latest_url(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_page_identifier(identifier):
            logger.log_warning("Page identifier '%s' was not valid" % identifier)
            return None

        # Return latest url
        latest_url = "https://www.gog.com/en/game/%s" % identifier
        return latest_url

    ############################################################
    # Purchases
    ############################################################

    # Owned games with slug, product id, page and title, from a cache under a day old or else LGOGDownloader's JSON list
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = self.get_purchases_cache_dir()
        cache_file_manifest = paths.join_paths(cache_dir, "gog_purchases_cache.json")

        # Load from cache if available
        gog_json = self.read_purchases_cache(cache_file_manifest, "GOG", verbose = verbose)

        # Fetch fresh data if not using cache
        if gog_json is None:
            gog_json = self._list_owned_games(verbose = verbose, exit_on_failure = exit_on_failure)
            if gog_json is None:
                return None
            self.write_purchases_cache(cache_dir, cache_file_manifest, gog_json, "GOG", verbose = verbose, pretend_run = pretend_run)

        # Parse json
        return [self._create_purchase(entry) for entry in gog_json]

    # LGOGDownloader's JSON game list, read back from a temporary file; None, logged, when it fails
    def _list_owned_games(self, verbose = False, exit_on_failure = False):

        # Get tool
        gog_tool = programs.find_tool_program("LGOGDownloader")
        if not gog_tool:
            return None

        # List purchases into a temporary manifest
        with fileops.temporary_directory(verbose = verbose) as tmp_dir_result:
            if not tmp_dir_result:
                return None
            tmp_file_manifest = paths.join_paths(tmp_dir_result, "manifest.json")

            # Run list command
            code = command.run_returncode_command(
                cmd = [
                    gog_tool,
                    "--list", "j"
                ],
                options = commandbase.create_command_options(
                    stdout = tmp_file_manifest),
                verbose = False,
                exit_on_failure = exit_on_failure)
            if code != 0:
                logger.log_error("Unable to find gog purchases")
                return None

            # Get gog json
            gog_json = serialization.read_json_file(
                src = tmp_file_manifest,
                verbose = verbose,
                exit_on_failure = False)
            if not isinstance(gog_json, list) or not all(isinstance(entry, dict) for entry in gog_json):
                logger.log_error("Unable to parse gog game list")
                return None
            return gog_json

    # Purchase with slug, product id, page and title for one game list entry
    def _create_purchase(self, entry):
        line_appname = str(entry.get("gamename", ""))
        line_appid = str(entry.get("product_id", ""))
        line_title = str(entry.get("title", ""))
        purchase = jsondata.JsonData(
            json_data = {},
            json_platform = self.get_platform())
        purchase.set_value(config.JSON_KEY_STORE_APPNAME, line_appname)
        purchase.set_value(config.JSON_KEY_STORE_APPID, line_appid)
        purchase.set_value(config.JSON_KEY_STORE_APPURL, self.get_latest_url(line_appname))
        purchase.set_value(config.JSON_KEY_STORE_NAME, line_title)
        return purchase

    ############################################################
    # Json
    ############################################################

    # Merge in manifest save paths and registry keys matched by GOG product id, then apply the base path cleanup
    def augment_jsondata(
        self,
        json_data,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get existing paths and keys
        game_paths = list(json_data.get_value(config.JSON_KEY_STORE_PATHS))
        game_keys = list(json_data.get_value(config.JSON_KEY_STORE_KEYS))

        # Augment by manifest
        manifest_entry = manifest.get_manifest_instance().find_entry_by_gogid(
            gogid = identifier)
        if manifest_entry:
            manifest_paths = manifest_entry.get_paths(config.TOKEN_GAME_INSTALL_DIR)
            game_paths = list(set(game_paths).union(manifest_paths))
            game_keys = list(set(game_keys).union(manifest_entry.get_keys()))

        # Apply base path cleaning logic
        json_data.set_value(config.JSON_KEY_STORE_PATHS, game_paths)
        json_data.set_value(config.JSON_KEY_STORE_KEYS, game_keys)
        return super().augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Slug, title, page and the preferred-OS installer version from the GOG products API; None when unreachable
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

        # Get gog url
        gog_url = "https://api.gog.com/products/%s?expand=downloads" % identifier
        if not network.is_url_reachable(gog_url):
            return None

        # Get gog json
        gog_json = network.get_remote_json(
            url = gog_url,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not gog_json:
            logger.log_error("Unable to find gog release information from '%s'" % gog_url)
            return None

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.JSON_KEY_STORE_APPID, identifier)
        json_data.set_value(config.JSON_KEY_STORE_APPNAME, str(gog_json.get("slug", "")))
        json_data.set_value(config.JSON_KEY_STORE_NAME, str(gog_json.get("title", "")).strip())
        self._set_installer_buildid(json_data, gog_json)
        self._set_product_url(json_data, gog_json)
        return self.augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Set the build id from the first installer for the preferred OS, the default when its version is empty
    def _set_installer_buildid(self, json_data, gog_json):
        for installer in gog_json.get("downloads", {}).get("installers", []):
            if installer.get("os") != self.get_preferred_platform():
                continue
            installer_version = installer.get("version", config.DEFAULT_BUILDID)
            if not installer_version:
                installer_version = config.DEFAULT_BUILDID
            json_data.set_value(config.JSON_KEY_STORE_BUILDID, installer_version)
            return

    # Set the store page url: the product card when reachable, else the slug's page when that is
    def _set_product_url(self, json_data, gog_json):
        appurl = gog_json.get("links", {}).get("product_card", "")
        if not network.is_url_reachable(appurl):
            appurl = self.get_latest_url(str(gog_json.get("slug", "")))
        if network.is_url_reachable(appurl):
            json_data.set_value(config.JSON_KEY_STORE_APPURL, appurl)

    ############################################################
    # Metadata
    ############################################################

    # Description, developer, publisher, release date and genres scraped from the game's GOG page, with retries
    def get_latest_metadata(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_metadata_identifier(identifier):
            logger.log_warning("Metadata identifier '%s' was not valid" % identifier)
            return None

        # Scrape the game page with retries
        return self.scrape_with_retries(
            scrape_func = lambda web_driver: self._scrape_metadata_page(web_driver, identifier, verbose = verbose),
            operation_name = "GOG metadata fetch for '%s'" % identifier,
            verbose = verbose,
            pretend_run = pretend_run)

    # Load the game page and read its description and detail rows into a metadata entry
    def _scrape_metadata_page(self, web_driver, identifier, verbose = False):

        # Load url
        success = webpage.load_url(web_driver, identifier)
        if not success:
            raise webpage.ScrapeFailed("Failed to load URL: %s" % identifier)

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()

        # Look for game description (now with improved error handling in webpage module)
        element_game_description = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "description"}),
            verbose = verbose,
            exit_on_failure = False)
        if element_game_description:
            raw_game_description = webpage.get_element_children_text(element_game_description)
            if raw_game_description:
                metadata_entry.set_description(raw_game_description)

        # Look for game details (now with improved error handling in webpage module)
        elements_details = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "details__row"}),
            all_elements = True,
            verbose = verbose,
            exit_on_failure = False)
        for elements_detail in elements_details or []:
            element_detail_text = webpage.get_element_children_text(elements_detail)
            if element_detail_text:
                _read_detail_row(element_detail_text.strip(), metadata_entry)
        return metadata_entry

    ############################################################
    # Assets
    ############################################################

    # A box front from the metadata asset collectors, or the YouTube embed found on the game page; None for other types
    def get_latest_asset_url(
        self,
        identifier,
        asset_type,
        game_name = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_asset_identifier(identifier):
            logger.log_warning("Asset identifier '%s' was not valid" % identifier)
            return None

        # Latest asset url
        latest_asset_url = None

        # BoxFront
        if asset_type == config.AssetType.BOXFRONT:
            latest_asset_url = metadataassetcollector.find_metadata_asset(
                game_platform = self.get_platform(),
                game_name = game_name if game_name else identifier,
                asset_type = asset_type,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = webfetch.get_matching_url(
                url = identifier,
                base_url = "https://www.youtube.com/embed",
                starts_with = "https://www.youtube.com/embed",
                ends_with = "enablejsapi=1",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Return latest asset url
        return latest_asset_url

    ############################################################
    # Install
    ############################################################

    # Where the game with this product id installs: its own folder under the store install dir
    def get_install_path(self, identifier):
        return paths.join_paths(self.get_install_dir(), identifier)

    # Check if installed
    def is_installed(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        if not self.is_valid_install_identifier(identifier):
            return False
        return paths.does_directory_contain_files(self.get_install_path(identifier))

    # Install the game into its install path with HeroicGogDL for the preferred OS; True when the tool exits cleanly
    def install(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_install_identifier(identifier):
            logger.log_warning("Install identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        python_tool = programs.find_tool_program("PythonVenvPython")
        if not python_tool:
            return False

        # Get script
        gogdl_script, auth_json = find_gogdl_script()
        if not gogdl_script:
            return False

        # Get install command
        install_cmd = self._get_gogdl_install_cmd(python_tool, gogdl_script, auth_json, identifier)

        # Run install command
        code = command.run_returncode_command(
            cmd = install_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0

    # HeroicGogDL download command for the preferred OS, as gogdl names it, into the game's install path
    def _get_gogdl_install_cmd(self, python_tool, gogdl_script, auth_json, identifier):
        return [
            python_tool,
            gogdl_script,
            "--auth-config-path",
            auth_json,
            "download",
            identifier,
            "--platform", gogdl_platforms.get(self.get_preferred_platform(), self.get_preferred_platform()),
            "--path", self.get_install_path(identifier)
        ]

    ############################################################
    # Download
    ############################################################

    # Fetch installers, extras and DLC with LGOGDownloader, fold DLC extras into extra, and move it all into output_dir
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

        # Get tool
        gog_tool = programs.find_tool_program("LGOGDownloader")
        if not gog_tool:
            return False

        # Download into a temporary directory and move it to the output
        with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir_result:
            if not tmp_dir_result:
                return False

            # Download game files
            if not self._fetch_lgog_download(gog_tool, identifier, tmp_dir_result, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                return False

            # Move downloaded files
            if not _move_to_output(tmp_dir_result, output_dir, clean_output = clean_output, show_progress = show_progress, skip_existing = skip_existing, skip_identical = skip_identical,
                verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                return False

        # Check result
        return paths.does_directory_contain_files(output_dir)

    # Fetch installers, extras and DLC into download_dir with LGOGDownloader, then fold DLC extras into extra
    def _fetch_lgog_download(self, gog_tool, identifier, download_dir, verbose = False, pretend_run = False, exit_on_failure = False):

        # Get download command
        download_cmd = [
            gog_tool,
            "--download",
            "--game=^%s$" % identifier,
            "--platform=%s" % self.get_preferred_platform(),
            "--directory=%s" % download_dir,
            "--check-free-space",
            "--threads=1",
            "--subdir-game=.",
            "--subdir-extras=extra",
            "--subdir-dlc=dlc"
        ]
        if isinstance(self.includes, str) and len(self.includes):
            download_cmd += [
                "--include=%s" % self.includes
            ]
        if isinstance(self.excludes, str) and len(self.excludes):
            download_cmd += [
                "--exclude=%s" % self.excludes
            ]

        # Run download command
        code = command.run_returncode_command(
            cmd = download_cmd,
            options = commandbase.create_command_options(
                blocking_processes = [gog_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Move dlc extra into main extra
        _merge_dlc_extras(download_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        return True

    ############################################################
