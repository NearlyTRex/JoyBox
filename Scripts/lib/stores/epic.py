# Imports
import os, os.path
import sys
import json

# Local imports
import config
import datautils
import command
import archive
import programs
import serialization
import system
import logger
import environment
import fileops
import ini
import jsondata
import webpage
import storebase
import strings
import metadataentry
import paths

# Epic store
class Epic(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get user details
        self.username = ini.GetIniValue("UserData.Epic", "epic_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Epic", "epic_install_dir")
        if not paths.is_path_valid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.EPIC.val()

    # Get type
    def GetType(self):
        return config.StoreType.EPIC

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_EPIC_GAMES

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_EPIC_GAMES

    # Get key
    def GetKey(self):
        return config.json_key_epic

    # Get identifier keys
    def GetIdentifierKeys(self):
        return {
            config.StoreIdentifierType.INFO: config.json_key_store_appname,
            config.StoreIdentifierType.INSTALL: config.json_key_store_appname,
            config.StoreIdentifierType.LAUNCH: config.json_key_store_appname,
            config.StoreIdentifierType.DOWNLOAD: config.json_key_store_appname,
            config.StoreIdentifierType.ASSET: config.json_key_store_appname,
            config.StoreIdentifierType.METADATA: config.json_key_store_appurl,
            config.StoreIdentifierType.PAGE: config.json_key_store_appname
        }

    # Get user name
    def GetUserName(self):
        return self.username

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    # Check if store can handle installing
    def CanHandleInstalling(self):
        return True

    # Check if store can handle launching
    def CanHandleLaunching(self):
        return True

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
        legendary_script = None
        if programs.IsToolInstalled("Legendary"):
            legendary_script = programs.GetToolProgram("Legendary")
        if not legendary_script:
            logger.log_error("Legendary was not found")
            return False

        # Get login command
        login_cmd = [
            python_tool,
            legendary_script,
            "auth"
        ]

        # Run login command
        code = command.RunInteractiveCommand(
            cmd = login_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Should be successful
        self.SetLoggedIn(True)
        return True

    ############################################################
    # Page
    ############################################################

    # Get latest url
    def GetLatestUrl(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidPageIdentifier(identifier):
            logger.log_warning("Page identifier '%s' was not valid" % identifier)
            return None

        # Connect to web
        web_driver = self.WebConnect(
            headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Get search terms
        search_terms = strings.encode_url_string(identifier.strip(), use_plus = True)

        # Load url
        success = webpage.LoadUrl(web_driver, "https://store.epicgames.com/en-US/browse?sortBy=relevancy&sortDir=DESC&q=" + search_terms)
        if not success:
            return None

        # Find the root container element
        element_search_result = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "css-1ufzxyu"}),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not element_search_result:
            return None

        # Score each potential title compared to the original title
        scores_list = []
        game_cells = webpage.GetElement(
            parent = element_search_result,
            locator = webpage.ElementLocator({"class": "css-2mlzob"}),
            all_elements = True)
        if game_cells:
            for game_cell in game_cells:

                # Get possible title
                game_title_element = webpage.GetElement(
                    parent = game_cell,
                    locator = webpage.ElementLocator({"class": "css-lgj0h8"}),
                    verbose = verbose)
                game_cell_text = webpage.GetElementChildrenText(game_title_element)

                # Add comparison score
                score_entry = {}
                score_entry["element"] = game_cell
                score_entry["ratio"] = strings.get_string_similarity_ratio(identifier, game_cell_text)
                scores_list.append(score_entry)

        # Get the best url match
        appurl = None
        for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
            game_cell = score_entry["element"]
            game_link_element = webpage.GetElement(
                parent = game_cell,
                locator = webpage.ElementLocator({"class": "css-1k3j1r9"}),
                verbose = verbose)
            if game_link_element:
                appurl = webpage.GetElementAttribute(game_link_element, "href")
                break

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Return appurl
        return appurl

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
        cache_file_purchases = paths.join_paths(cache_dir, "epic_purchases_cache.json")

        # Check if cache exists and is recent (less than 24 hours old)
        use_cache = False
        if paths.does_path_exist(cache_file_purchases):
            cache_age_hours = paths.get_file_age_in_hours(cache_file_purchases)
            if cache_age_hours < 24:
                use_cache = True
                if verbose:
                    logger.log_info("Using cached Epic purchases data (%.1f hours old)" % cache_age_hours)

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
                    logger.log_warning("Failed to load Epic cache, will fetch fresh data")
                use_cache = False

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            logger.log_error("PythonVenvPython was not found")
            return None

        # Get script
        legendary_script = None
        if programs.IsToolInstalled("Legendary"):
            legendary_script = programs.GetToolProgram("Legendary")
        if not legendary_script:
            logger.log_error("Legendary was not found")
            return None

        # Get list command
        list_cmd = [
            python_tool,
            legendary_script,
            "list",
            "--json"
        ]

        # Run list command
        list_output = command.RunOutputCommand(
            cmd = list_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if len(list_output) == 0:
            logger.log_error("Unable to find epic purchases")
            return None

        # Get epic json
        epic_json = []
        try:
            epic_json = json.loads(list_output)
        except Exception as e:
            logger.log_error(e)
            logger.log_error("Unable to parse epic game list")
            logger.log_error("Received output:\n%s" % list_output)
            return None

        # Parse output
        purchases = []
        purchases_data = []
        for entry in epic_json:

            # Gather info
            line_appname = str(entry.get("app_name", ""))
            line_title = str(entry.get("app_title", ""))
            line_buildid = str(entry.get("asset_infos", {}).get("Windows", {}).get("build_version", config.default_buildid))

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.GetPlatform())
            purchase.set_value(config.json_key_store_appname, line_appname)
            purchase.set_value(config.json_key_store_appurl, "")
            purchase.set_value(config.json_key_store_name, line_title)
            purchase.set_value(config.json_key_store_buildid, line_buildid)
            purchases.append(purchase)

            # Store data for caching
            purchases_data.append({
                config.json_key_store_appname: line_appname,
                config.json_key_store_appurl: "",
                config.json_key_store_name: line_title,
                config.json_key_store_buildid: line_buildid
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
            logger.log_info("Saved Epic purchases data to cache")
        elif not success and verbose:
            logger.log_warning("Failed to save Epic cache")
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
        legendary_script = None
        if programs.IsToolInstalled("Legendary"):
            legendary_script = programs.GetToolProgram("Legendary")
        if not legendary_script:
            logger.log_error("Legendary was not found")
            return None

        # Get info command
        info_cmd = [
            python_tool,
            legendary_script,
            "info", identifier,
            "--json"
        ]

        # Run info command
        info_output = command.RunOutputCommand(
            cmd = info_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0 or "No game information available" in info_output:
            logger.log_error("Unable to find epic information for '%s'" % identifier)
            return None

        # Get epic json
        epic_json = {}
        try:
            epic_json = json.loads(info_output)
        except Exception as e:
            logger.log_error(e)
            logger.log_error("Unable to parse epic game information for '%s'" % identifier)
            logger.log_error("Received output:\n%s" % info_output)
            return None

        # Build jsondata
        json_data = self.CreateDefaultJsondata()
        json_data.set_value(config.json_key_store_appname, identifier)
        json_data.set_value(config.json_key_store_name, epic_json.get("game", {}).get("title", "").strip())
        json_data.set_value(config.json_key_store_buildid, epic_json.get("game", {}).get("version", config.default_buildid).strip())
        cloud_save_folder = epic_json.get("game", {}).get("cloud_save_folder")
        if cloud_save_folder:
            base_path = None
            if json_data.has_key(config.json_key_store_installdir):
                base_path = paths.join_paths(
                    config.token_game_install_dir,
                    json_data.get_value(config.json_key_store_installdir)
                )
            json_data.set_value(config.json_key_store_paths, [
                storebase.CreateTokenizedPath(cloud_save_folder.strip(), base_path)
            ])
        return self.AugmentJsondata(
            json_data = json_data,
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Metadata
    ############################################################

    # Get latest metadata
    def GetLatestMetadata(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidMetadataIdentifier(identifier):
            logger.log_warning("Metadata identifier '%s' was not valid" % identifier)
            return None

        # Store web driver for cleanup
        web_driver = None

        # Cleanup function
        def cleanup_driver():
            if web_driver:
                self.WebDisconnect(
                    web_driver = web_driver,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)

        # Fetch function
        def attempt_metadata_fetch():
            nonlocal web_driver

            # Connect to web
            web_driver = self.WebConnect(
                headless = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not web_driver:
                raise Exception("Failed to connect to web driver")

            # Load url
            success = webpage.LoadUrl(web_driver, identifier)
            if not success:
                raise Exception("Failed to load URL: %s" % identifier)

            # Create metadata entry
            metadata_entry = metadataentry.MetadataEntry()

            # Look for game description
            element_game_description = webpage.WaitForElement(
                driver = web_driver,
                locator = webpage.ElementLocator({"id": "about-long-description"}),
                wait_time = 15,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if element_game_description:
                raw_game_description = webpage.GetElementChildrenText(element_game_description)
                if raw_game_description:
                    metadata_entry.set_description(raw_game_description)

            # Look for game genres
            elements_potential_genres = webpage.GetElement(
                parent = web_driver,
                locator = webpage.ElementLocator({"class": "css-8f0505"}),
                all_elements = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if elements_potential_genres:
                for element_potential_genre in elements_potential_genres:
                    potential_text = webpage.GetElementChildrenText(element_potential_genre)
                    if potential_text and "Genres" in potential_text:
                        element_game_genres = webpage.GetElement(
                            parent = element_potential_genre,
                            locator = webpage.ElementLocator({"class": "css-cyjj8t"}),
                            all_elements = True,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = False)
                        if element_game_genres:
                            game_genres = []
                            for element_game_genre in element_game_genres:
                                game_genre_text = webpage.GetElementChildrenText(element_game_genre)
                                if game_genre_text:
                                    game_genres.append(game_genre_text)
                            if game_genres:
                                metadata_entry.set_genre(";".join(game_genres))

            # Look for game details
            elements_details = webpage.GetElement(
                parent = web_driver,
                locator = webpage.ElementLocator({"class": "css-s97i32"}),
                all_elements = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if elements_details:
                for elements_detail in elements_details:
                    element_detail_text = webpage.GetElementChildrenText(elements_detail)
                    if element_detail_text:

                        # Developer
                        if strings.does_string_start_with_substring(element_detail_text, "Developer"):
                            developer_text = strings.trim_substring_from_start(element_detail_text, "Developer").strip()
                            metadata_entry.set_developer(developer_text)

                        # Publisher
                        elif strings.does_string_start_with_substring(element_detail_text, "Publisher"):
                            published_text = strings.trim_substring_from_start(element_detail_text, "Publisher").strip()
                            metadata_entry.set_publisher(published_text)

                        # Release
                        elif strings.does_string_start_with_substring(element_detail_text, "Release Date"):
                            release_text = strings.trim_substring_from_start(element_detail_text, "Release Date").strip()
                            release_text = strings.convert_date_string(release_text, "%m/%d/%y", "%Y-%m-%d")
                            metadata_entry.set_release(release_text)
            return metadata_entry

        # Use retry function with cleanup
        result = datautils.retry_with_backoff(
            func = attempt_metadata_fetch,
            cleanup_func = cleanup_driver,
            max_retries = 3,
            initial_delay = 2,
            backoff_factor = 2,
            verbose = verbose,
            operation_name = "Epic metadata fetch for '%s'" % identifier)

        # Final cleanup
        cleanup_driver()
        return result

    ############################################################
