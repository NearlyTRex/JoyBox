# Imports
import os, os.path
import sys
import json

# Local imports
import config
import command
import programs
import system
import environment
import network
import ini
import jsondata
import webpage
import storebase
import metadataentry
import metadataassetcollector
import manifest

# GOG store
class GOG(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get username
        self.username = ini.GetIniValue("UserData.GOG", "gog_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

        # Get email
        self.email = ini.GetIniValue("UserData.GOG", "gog_email")
        if not self.email:
            raise RuntimeError("Ini file does not have a valid email")

        # Get platform
        self.platform = ini.GetIniValue("UserData.GOG", "gog_platform")
        if not self.platform:
            raise RuntimeError("Ini file does not have a valid platform")

        # Get includes
        self.includes = ini.GetIniValue("UserData.GOG", "gog_includes")

        # Get excludes
        self.excludes = ini.GetIniValue("UserData.GOG", "gog_excludes")

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.GOG", "gog_install_dir")
        if not system.IsPathValid(self.install_dir):
            raise RuntimeError("Ini file does not have a valid install dir")

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return config.StoreType.GOG.val()

    # Get type
    def GetType(self):
        return config.StoreType.GOG

    # Get platform
    def GetPlatform(self):
        return config.Platform.COMPUTER_GOG

    # Get supercategory
    def GetSupercategory(self):
        return config.Supercategory.ROMS

    # Get category
    def GetCategory(self):
        return config.Category.COMPUTER

    # Get subcategory
    def GetSubcategory(self):
        return config.Subcategory.COMPUTER_GOG

    # Get key
    def GetKey(self):
        return config.json_key_gog

    # Get identifier keys
    def GetIdentifierKeys(self):
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
    def GetPreferredPlatform(self):
        return self.platform

    # Get user name
    def GetUserName(self):
        return self.username

    # Get email
    def GetEmail(self):
        return self.email

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

    # Login LGOGDownloader
    def LoginLGOGDownloader(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get tool
        gog_tool = None
        if programs.IsToolInstalled("LGOGDownloader"):
            gog_tool = programs.GetToolProgram("LGOGDownloader")
        if not gog_tool:
            system.LogError("LGOGDownloader was not found")
            return None

        # Get login command
        login_cmd = [
            gog_tool,
            "--login"
        ]

        # Run login command
        code = command.RunInteractiveCommand(
            cmd = login_cmd,
            options = command.CreateCommandOptions(
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
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return False

        # Get script
        login_script = None
        if programs.IsToolInstalled("HeroicGogDL"):
            login_script = programs.GetToolPathConfigValue("HeroicGogDL", "login_script")
            auth_json = programs.GetToolPathConfigValue("HeroicGogDL", "auth_json")
        if not login_script and not auth_json:
            system.LogError("HeroicGogDL was not found")
            return False

        # Get login command
        login_cmd = [
            python_tool,
            login_script,
            auth_json
        ]

        # Run login command
        code = command.RunInteractiveCommand(
            cmd = login_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code != 0)

    # Login
    def Login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if already logged in
        if self.IsLoggedIn():
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
            system.LogWarning("Page identifier '%s' was not valid" % identifier)
            return None

        # Return latest url
        latest_url = "https://www.gog.com/en/game/%s" % identifier
        return latest_url

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
        cache_file_manifest = system.JoinPaths(cache_dir, "gog_purchases_cache.json")

        # Check if cache exists and is recent (less than 24 hours old)
        use_cache = False
        if system.DoesPathExist(cache_file_manifest):
            cache_age_hours = system.GetFileAgeInHours(cache_file_manifest)
            if cache_age_hours < 24:
                use_cache = True
                if verbose:
                    system.LogInfo("Using cached GOG purchases data (%.1f hours old)" % cache_age_hours)

        # Load from cache if available
        if use_cache:
            gog_json = system.ReadJsonFile(
                src = cache_file_manifest,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not gog_json:
                if verbose:
                    system.LogWarning("Failed to load GOG cache, will fetch fresh data")
                use_cache = False

        # Fetch fresh data if not using cache
        if not use_cache:
            # Get tool
            gog_tool = None
            if programs.IsToolInstalled("LGOGDownloader"):
                gog_tool = programs.GetToolProgram("LGOGDownloader")
            if not gog_tool:
                system.LogError("LGOGDownloader was not found")
                return None

            # Create temporary directory
            tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
            if not tmp_dir_success:
                return None

            # Get temporary paths
            tmp_file_manifest = system.JoinPaths(tmp_dir_result, "manifest.json")

            # Get list command
            list_cmd = [
                gog_tool,
                "--list", "j"
            ]

            # Run list command
            code = command.RunReturncodeCommand(
                cmd = list_cmd,
                options = command.CreateCommandOptions(
                    stdout = tmp_file_manifest),
                verbose = False,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if code != 0:
                system.LogError("Unable to find gog purchases")
                return False

            # Get gog json
            gog_json = system.ReadJsonFile(
                src = tmp_file_manifest,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not gog_json:
                system.LogError("Unable to parse gog game list")
                return None

            # Save to cache
            system.MakeDirectory(cache_dir, verbose = verbose, pretend_run = pretend_run)
            success = system.WriteJsonFile(
                src = cache_file_manifest,
                json_data = gog_json,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if success and verbose:
                system.LogInfo("Saved GOG purchases data to cache")
            elif not success and verbose:
                system.LogWarning("Failed to save GOG cache")

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
                json_platform = self.GetPlatform())
            purchase.set_value(config.json_key_store_appname, line_appname)
            purchase.set_value(config.json_key_store_appid, line_appid)
            purchase.set_value(config.json_key_store_appurl, self.GetLatestUrl(line_appname))
            purchase.set_value(config.json_key_store_name, line_title)
            purchases.append(purchase)
        return purchases

    ############################################################
    # Json
    ############################################################

    # Augment jsondata
    def AugmentJsondata(
        self,
        json_data,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Augment by manifest
        manifest_entry = manifest.GetManifestInstance().find_entry_by_gogid(
            gogid = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if manifest_entry:

            # Get existing paths and keys
            game_paths = set(json_data.get_value(config.json_key_store_paths))
            game_keys = set(json_data.get_value(config.json_key_store_keys))

            # Update paths and keys
            game_paths = game_paths.union(manifest_entry.get_paths(config.token_game_install_dir))
            game_keys = game_keys.union(manifest_entry.get_keys())

            # Save paths and keys
            json_data.set_value(config.json_key_store_paths, system.SortStrings(game_paths))
            json_data.set_value(config.json_key_store_keys, system.SortStrings(game_keys))
        return json_data

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
            system.LogWarning("Info identifier '%s' was not valid" % identifier)
            return None

        # Get gog url
        gog_url = "https://api.gog.com/products/%s?expand=downloads" % identifier
        if not network.IsUrlReachable(gog_url):
            return None

        # Get gog json
        gog_json = network.GetRemoteJson(
            url = gog_url,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not gog_json:
            system.LogError("Unable to find gog release information from '%s'" % gog_url)
            return None

        # Build jsondata
        json_data = self.CreateDefaultJsondata()
        json_data.set_value(config.json_key_store_appid, identifier)
        json_data.set_value(config.json_key_store_appname, str(gog_json.get("slug", "")))
        json_data.set_value(config.json_key_store_name, str(gog_json.get("title", "")).strip())
        for installer in gog_json.get("downloads", {}).get("installers", []):
            if installer.get("os") == self.GetPreferredPlatform():
                installer_version = installer.get("version", config.default_buildid)
                if not installer_version:
                    installer_version = config.default_buildid
                json_data.set_value(config.json_key_store_buildid, installer_version)
                break
        appurl = gog_json.get("links", {}).get("product_card", "")
        if not network.IsUrlReachable(appurl):
            appurl = self.GetLatestUrl(str(gog_json.get("slug", "")))
        if network.IsUrlReachable(appurl):
            json_data.set_value(config.json_key_store_appurl, appurl)
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
            system.LogWarning("Metadata identifier '%s' was not valid" % identifier)
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

            # Look for game description (now with improved error handling in webpage module)
            element_game_description = webpage.WaitForElement(
                driver = web_driver,
                locator = webpage.ElementLocator({"class": "description"}),
                wait_time = 15,  # 15 second timeout
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if element_game_description:
                raw_game_description = webpage.GetElementChildrenText(element_game_description)
                if raw_game_description:
                    metadata_entry.set_description(raw_game_description)

            # Look for game details (now with improved error handling in webpage module)
            elements_details = webpage.GetElement(
                parent = web_driver,
                locator = webpage.ElementLocator({"class": "details__row"}),
                all_elements = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if elements_details:
                for elements_detail in elements_details:
                    element_detail_text = webpage.GetElementChildrenText(elements_detail)
                    if element_detail_text:
                        element_detail_text = element_detail_text.strip()

                        # Developer/Publisher
                        if system.DoesStringStartWithSubstring(element_detail_text, "Company:"):
                            company_text = system.TrimSubstringFromStart(element_detail_text, "Company:").strip()
                            for index, company_part in enumerate(company_text.split("/")):
                                if index == 0:
                                    metadata_entry.set_developer(company_part.strip())
                                elif index == 1:
                                    metadata_entry.set_publisher(company_part.strip())

                        # Release
                        elif system.DoesStringStartWithSubstring(element_detail_text, "Release date:"):
                            release_text = system.TrimSubstringFromStart(element_detail_text, "Release date:").strip()
                            release_text = system.ConvertDateString(release_text, "%B %d, %Y", "%Y-%m-%d")
                            metadata_entry.set_release(release_text)

                        # Genre
                        elif system.DoesStringStartWithSubstring(element_detail_text, "Genre:"):
                            genre_text = system.TrimSubstringFromStart(element_detail_text, "Genre:").strip().replace(" - ", ";")
                            metadata_entry.set_genre(genre_text)
            return metadata_entry

        # Use retry function with cleanup
        result = system.RetryWithBackoff(
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
    def GetLatestAssetUrl(
        self,
        identifier,
        asset_type,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidAssetIdentifier(identifier):
            system.LogWarning("Asset identifier '%s' was not valid" % identifier)
            return None

        # Latest asset url
        latest_asset_url = None

        # BoxFront
        if asset_type == config.AssetType.BOXFRONT:
            latest_asset_url = metadataassetcollector.FindMetadataAsset(
                game_platform = self.GetPlatform(),
                game_name = identifier,
                asset_type = asset_type,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Video
        elif asset_type == config.AssetType.VIDEO:
            latest_asset_url = webpage.GetMatchingUrl(
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
    def Install(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidInstallIdentifier(identifier):
            system.LogWarning("Install identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return False

        # Get script
        gogdl_script = None
        if programs.IsToolInstalled("HeroicGogDL"):
            gogdl_script = programs.GetToolProgram("HeroicGogDL")
            auth_json = programs.GetToolPathConfigValue("HeroicGogDL", "auth_json")
        if not gogdl_script and not auth_json:
            system.LogError("HeroicGogDL was not found")
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
            "--path", os.path.join(self.GetInstallDir(), identifier)
        ]

        # Run login command
        code = command.RunReturncodeCommand(
            cmd = install_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return (code != 0)

    ############################################################
    # Launch
    ############################################################

    # Launch
    def Launch(
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
            system.LogWarning("Download identifier '%s' was not valid" % identifier)
            return False

        # Get tool
        gog_tool = None
        if programs.IsToolInstalled("LGOGDownloader"):
            gog_tool = programs.GetToolProgram("LGOGDownloader")
        if not gog_tool:
            system.LogError("LGOGDownloader was not found")
            return None

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Get temporary paths
        tmp_dir_extra = system.JoinPaths(tmp_dir_result, "extra")
        tmp_dir_dlc = system.JoinPaths(tmp_dir_result, "dlc")
        tmp_dir_dlc_extra = system.JoinPaths(tmp_dir_dlc, "extra")

        # Get download command
        download_cmd = [
            gog_tool,
            "--download",
            "--game=^%s$" % identifier,
            "--platform=%s" % self.GetPreferredPlatform(),
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
        code = command.RunReturncodeCommand(
            cmd = download_cmd,
            options = command.CreateCommandOptions(
                blocking_processes = [gog_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Move dlc extra into main extra
        if system.DoesDirectoryContainFiles(tmp_dir_dlc_extra):
            system.MoveContents(
                src = tmp_dir_dlc_extra,
                dest = tmp_dir_extra,
                skip_existing = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.RemoveDirectory(
                src = tmp_dir_dlc_extra,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Clean output
        if clean_output:
            system.RemoveDirectoryContents(
                src = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Move downloaded files
        success = system.MoveContents(
            src = tmp_dir_result,
            dest = output_dir,
            show_progress = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.RemoveDirectory(
                src = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return False

        # Delete temporary directory
        system.RemoveDirectory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check result
        return os.path.exists(output_dir)

    ############################################################
