# Imports
import os, os.path
import sys
import json

# Local imports
import config
import datautils
import command
import programs
import serialization
import system
import logger
import environment
import fileops
import network
import paths
import ini
import jsondata
import webpage
import storebase
import strings
import metadataentry
import metadataassetcollector
import manifest

# GOG store
class GOG(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get username
        self.username = ini.get_ini_value("UserData.GOG", "gog_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get email
        self.email = ini.get_ini_value("UserData.GOG", "gog_email")
        if not self.email:
            raise RuntimeError("Ini file does not have a valid email")

        # Get platform
        self.platform = ini.get_ini_value("UserData.GOG", "gog_platform")
        if not self.platform:
            raise RuntimeError("Ini file does not have a valid platform")

        # Get includes
        self.includes = ini.get_ini_value("UserData.GOG", "gog_includes")

        # Get excludes
        self.excludes = ini.get_ini_value("UserData.GOG", "gog_excludes")

        # Get install dir
        self.install_dir = ini.get_ini_path_value("UserData.GOG", "gog_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def get_name(self):
        return config.StoreType.GOG.val()

    # Get type
    def get_type(self):
        return config.StoreType.GOG

    # Get platform
    def get_platform(self):
        return config.Platform.COMPUTER_GOG

    # Get supercategory
    def get_supercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def get_category(self):
        return config.Category.COMPUTER

    # Get subcategory
    def get_subcategory(self):
        return config.Subcategory.COMPUTER_GOG

    # Get key
    def get_key(self):
        return config.json_key_gog

    # Get identifier keys
    def get_identifier_keys(self):
        return {
            config.StoreIdentifierType.INFO: config.json_key_store_appid,
            config.StoreIdentifierType.INSTALL: config.json_key_store_appid,
            config.StoreIdentifierType.LAUNCH: config.json_key_store_appname,
            config.StoreIdentifierType.DOWNLOAD: config.json_key_store_appname,
            config.StoreIdentifierType.ASSET: config.json_key_store_appurl,
            config.StoreIdentifierType.METADATA: config.json_key_store_appurl,
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

    # Get install dir
    def get_install_dir(self):
        return self.install_dir

    # Check if store can handle installing
    def can_handle_installing(self):
        return True

    # Check if store can handle launching
    def can_handle_launching(self):
        return True

    # Check if purchases can be imported
    def can_import_purchases(self):
        return True

    # Check if purchases can be downloaded
    def can_download_purchases(self):
        return True

    ############################################################
    # Connection
    ############################################################

    # Login LGOGDownloader
    def LoginLGOGDownloader(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        gog_tool = None
        if programs.is_tool_installed("LGOGDownloader"):
            gog_tool = programs.get_tool_program("LGOGDownloader")
        if not gog_tool:
            logger.log_error("LGOGDownloader was not found")
            return None

        # Get login command
        login_cmd = [
            gog_tool,
            "--login"
        ]

        # Run login command
        code = command.run_interactive_command(
            cmd = login_cmd,
            options = command.create_command_options(
                blocking_processes = [gog_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    # Login HeroicGogDL
    def LoginHeroicGogDL(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        python_tool = None
        if programs.is_tool_installed("PythonVenvPython"):
            python_tool = programs.get_tool_program("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return False

        # Get script
        login_script = None
        if programs.is_tool_installed("HeroicGogDL"):
            login_script = programs.get_tool_path_config_value("HeroicGogDL", "login_script")
            auth_json = programs.get_tool_path_config_value("HeroicGogDL", "auth_json")
        if not login_script and not auth_json:
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
        return (code != 0)

    # Login
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.is_logged_in():
            return True

        # Login LGOGDownloader
        success = self.LoginLGOGDownloader(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Login HeroicGogDL
        success = self.LoginHeroicGogDL(
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

    # Get latest url
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

    # Get purchases
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get cache file path
        cache_dir = environment.get_cache_root_dir()
        cache_file_manifest = paths.join_paths(cache_dir, "gog_purchases_cache.json")

        # Check if cache exists and is recent (less than 24 hours old)
        use_cache = False
        if paths.does_path_exist(cache_file_manifest):
            cache_age_hours = paths.get_file_age_in_hours(cache_file_manifest)
            if cache_age_hours < 24:
                use_cache = True
                if verbose:
                    logger.log_info("Using cached GOG purchases data (%.1f hours old)" % cache_age_hours)

        # Load from cache if available
        if use_cache:
            gog_json = serialization.read_json_file(
                src = cache_file_manifest,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not gog_json:
                if verbose:
                    logger.log_warning("Failed to load GOG cache, will fetch fresh data")
                use_cache = False

        # Fetch fresh data if not using cache
        if not use_cache:
            # Get tool
            gog_tool = None
            if programs.is_tool_installed("LGOGDownloader"):
                gog_tool = programs.get_tool_program("LGOGDownloader")
            if not gog_tool:
                logger.log_error("LGOGDownloader was not found")
                return None

            # Create temporary directory
            tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose)
            if not tmp_dir_success:
                return None

            # Get temporary paths
            tmp_file_manifest = paths.join_paths(tmp_dir_result, "manifest.json")

            # Get list command
            list_cmd = [
                gog_tool,
                "--list", "j"
            ]

            # Run list command
            code = command.run_returncode_command(
                cmd = list_cmd,
                options = command.create_command_options(
                    stdout = tmp_file_manifest),
                verbose = False,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if code != 0:
                logger.log_error("Unable to find gog purchases")
                return False

            # Get gog json
            gog_json = serialization.read_json_file(
                src = tmp_file_manifest,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not gog_json:
                logger.log_error("Unable to parse gog game list")
                return None

            # Save to cache
            fileops.make_directory(cache_dir, verbose = verbose, pretend_run = pretend_run)
            success = serialization.write_json_file(
                src = cache_file_manifest,
                json_data = gog_json,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if success and verbose:
                logger.log_info("Saved GOG purchases data to cache")
            elif not success and verbose:
                logger.log_warning("Failed to save GOG cache")

        # Parse json
        purchases = []
        for entry in gog_json:

            # Gather info
            line_appname = str(entry.get("gamename", ""))
            line_appid = str(entry.get("product_id", ""))
            line_title = str(entry.get("title", ""))

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.get_platform())
            purchase.set_value(config.json_key_store_appname, line_appname)
            purchase.set_value(config.json_key_store_appid, line_appid)
            purchase.set_value(config.json_key_store_appurl, self.get_latest_url(line_appname))
            purchase.set_value(config.json_key_store_name, line_title)
            purchases.append(purchase)
        return purchases

    ############################################################
    # Json
    ############################################################

    # Augment jsondata
    def augment_jsondata(
        self,
        json_data,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get existing paths and keys
        game_paths = list(json_data.get_value(config.json_key_store_paths))
        game_keys = list(json_data.get_value(config.json_key_store_keys))

        # Augment by manifest
        manifest_entry = manifest.GetManifestInstance().find_entry_by_gogid(
            gogid = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if manifest_entry:
            manifest_paths = manifest_entry.get_paths(config.token_game_install_dir)
            game_paths = list(set(game_paths).union(manifest_paths))
            game_keys = list(set(game_keys).union(manifest_entry.get_keys()))

        # Apply base path cleaning logic
        json_data.set_value(config.json_key_store_paths, game_paths)
        json_data.set_value(config.json_key_store_keys, game_keys)
        return super().AugmentJsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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

        # Get gog url
        gog_url = "https://api.gog.com/products/%s?expand=downloads" % identifier
        if not network.is_url_reachable(gog_url):
            return None

        # Get gog json
        gog_json = network.get_remote_json(
            url = gog_url,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not gog_json:
            logger.log_error("Unable to find gog release information from '%s'" % gog_url)
            return None

        # Build jsondata
        json_data = self.create_default_jsondata()
        json_data.set_value(config.json_key_store_appid, identifier)
        json_data.set_value(config.json_key_store_appname, str(gog_json.get("slug", "")))
        json_data.set_value(config.json_key_store_name, str(gog_json.get("title", "")).strip())
        for installer in gog_json.get("downloads", {}).get("installers", []):
            if installer.get("os") == self.get_preferred_platform():
                installer_version = installer.get("version", config.default_buildid)
                if not installer_version:
                    installer_version = config.default_buildid
                json_data.set_value(config.json_key_store_buildid, installer_version)
                break
        appurl = gog_json.get("links", {}).get("product_card", "")
        if not network.is_url_reachable(appurl):
            appurl = self.get_latest_url(str(gog_json.get("slug", "")))
        if network.is_url_reachable(appurl):
            json_data.set_value(config.json_key_store_appurl, appurl)
        return self.augment_jsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Metadata
    ############################################################

    # Get latest metadata
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

        # Store web driver for cleanup
        web_driver = None

        # Cleanup function
        def cleanup_driver():
            if web_driver:
                self.web_disconnect(
                    web_driver = web_driver,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)

        # Fetch function
        def attempt_metadata_fetch():
            nonlocal web_driver

            # Connect to web
            web_driver = self.web_connect(
                headless = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not web_driver:
                raise Exception("Failed to connect to web driver")

            # Load url
            success = webpage.load_url(web_driver, identifier)
            if not success:
                raise Exception("Failed to load URL: %s" % identifier)

            # Create metadata entry
            metadata_entry = metadataentry.MetadataEntry()

            # Look for game description (now with improved error handling in webpage module)
            element_game_description = webpage.wait_for_element(
                driver = web_driver,
                locator = webpage.ElementLocator({"class": "description"}),
                wait_time = 15,  # 15 second timeout
                verbose = verbose,
                pretend_run = pretend_run,
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
                pretend_run = pretend_run,
                exit_on_failure = False)
            if elements_details:
                for elements_detail in elements_details:
                    element_detail_text = webpage.get_element_children_text(elements_detail)
                    if element_detail_text:
                        element_detail_text = element_detail_text.strip()

                        # Developer/Publisher
                        if strings.does_string_start_with_substring(element_detail_text, "Company:"):
                            company_text = strings.trim_substring_from_start(element_detail_text, "Company:").strip()
                            for index, company_part in enumerate(company_text.split("/")):
                                if index == 0:
                                    metadata_entry.set_developer(company_part.strip())
                                elif index == 1:
                                    metadata_entry.set_publisher(company_part.strip())

                        # Release
                        elif strings.does_string_start_with_substring(element_detail_text, "Release date:"):
                            release_text = strings.trim_substring_from_start(element_detail_text, "Release date:").strip()
                            release_text = strings.convert_date_string(release_text, "%B %d, %Y", "%Y-%m-%d")
                            metadata_entry.set_release(release_text)

                        # Genre
                        elif strings.does_string_start_with_substring(element_detail_text, "Genre:"):
                            genre_text = strings.trim_substring_from_start(element_detail_text, "Genre:").strip().replace(" - ", ";")
                            metadata_entry.set_genre(genre_text)
            return metadata_entry

        # Use retry function with cleanup
        result = datautils.retry_with_backoff(
            func = attempt_metadata_fetch,
            cleanup_func = cleanup_driver,
            max_retries = 3,
            initial_delay = 2,
            backoff_factor = 2,
            verbose = verbose,
            operation_name = "GOG metadata fetch for '%s'" % identifier)

        # Final cleanup
        cleanup_driver()
        return result

    ############################################################
    # Assets
    ############################################################

    # Get latest asset url
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
            latest_asset_url = metadataassetcollector.FindMetadataAsset(
                game_platform = self.get_platform(),
                game_name = game_name if game_name else identifier,
                asset_type = asset_type,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = webpage.get_matching_url(
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

    # Install
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
        python_tool = None
        if programs.is_tool_installed("PythonVenvPython"):
            python_tool = programs.get_tool_program("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return False

        # Get script
        gogdl_script = None
        if programs.is_tool_installed("HeroicGogDL"):
            gogdl_script = programs.get_tool_program("HeroicGogDL")
            auth_json = programs.get_tool_path_config_value("HeroicGogDL", "auth_json")
        if not gogdl_script and not auth_json:
            logger.log_error("HeroicGogDL was not found")
            return False

        # Get install command
        install_cmd = [
            python_tool,
            gogdl_script,
            "--auth-config-path",
            auth_json,
            "download",
            identifier,
            "--platform", "windows",
            "--path", os.path.join(self.get_install_dir(), identifier)
        ]

        # Run login command
        code = command.run_returncode_command(
            cmd = install_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return (code != 0)

    ############################################################
    # Launch
    ############################################################

    # Launch
    def launch(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    ############################################################
    # Download
    ############################################################

    # Download
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
        gog_tool = None
        if programs.is_tool_installed("LGOGDownloader"):
            gog_tool = programs.get_tool_program("LGOGDownloader")
        if not gog_tool:
            logger.log_error("LGOGDownloader was not found")
            return None

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Get temporary paths
        tmp_dir_extra = paths.join_paths(tmp_dir_result, "extra")
        tmp_dir_dlc = paths.join_paths(tmp_dir_result, "dlc")
        tmp_dir_dlc_extra = paths.join_paths(tmp_dir_dlc, "extra")

        # Get download command
        download_cmd = [
            gog_tool,
            "--download",
            "--game=^%s$" % identifier,
            "--platform=%s" % self.get_preferred_platform(),
            "--directory=%s" % tmp_dir_result,
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
            options = command.create_command_options(
                blocking_processes = [gog_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Move dlc extra into main extra
        if paths.does_directory_contain_files(tmp_dir_dlc_extra):
            fileops.move_contents(
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

        # Clean output
        if clean_output:
            fileops.remove_directory_contents(
                src = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Move downloaded files
        success = fileops.move_contents(
            src = tmp_dir_result,
            dest = output_dir,
            show_progress = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            fileops.remove_directory(
                src = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return False

        # Delete temporary directory
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check result
        return os.path.exists(output_dir)

    ############################################################
