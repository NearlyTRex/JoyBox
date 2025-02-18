# Imports
import os, os.path
import sys
import json

# Local imports
import config
import command
import programs
import system
import network
import ini
import jsondata
import webpage
import storebase
import metadataentry

# GOG store
class GOG(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get username
        self.username = ini.GetIniValue("UserData.GOG", "gog_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid username")

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

    # Get preferred platform
    def GetPreferredPlatform(self):
        return self.platform

    # Get user name
    def GetUserName(self):
        return self.username

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    ############################################################
    # Identifiers
    ############################################################

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.StoreIdentifierType.INFO:
            return json_wrapper.get_value(config.json_key_store_appid)
        elif identifier_type == config.StoreIdentifierType.INSTALL:
            return json_wrapper.get_value(config.json_key_store_appid)
        elif identifier_type == config.StoreIdentifierType.ASSET:
            return json_wrapper.get_value(config.json_key_store_appurl)
        elif identifier_type == config.StoreIdentifierType.METADATA:
            return json_wrapper.get_value(config.json_key_store_appurl)
        return json_wrapper.get_value(config.json_key_store_appname)

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
        code = command.RunBlockingCommand(
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
        code = command.RunBlockingCommand(
            cmd = login_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return (code != 0)

    # Login
    def Login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

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
        return success

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
    def GetPurchases(
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
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            system.LogError("Unable to find gog purchases")
            return False

        # Get gog json
        gog_json = {}
        try:
            if os.path.exists(tmp_file_manifest):
                with open(tmp_file_manifest, "r") as manifest_file:
                    gog_json = json.load(manifest_file)
        except Exception as e:
            system.LogError(e)
            system.LogError("Unable to parse gog game list")
            return None

        # Parse json
        purchases = []
        for entry in gog_json:

            # Gather info
            line_appname = entry["gamename"]
            line_appid = entry["product_id"]
            line_title = entry["title"]

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

        # Build game info
        game_info = {}
        game_info[config.json_key_store_appid] = identifier
        game_info[config.json_key_store_paths] = []
        game_info[config.json_key_store_keys] = []

        # Augment by json
        if "slug" in gog_json:
            appslug = gog_json["slug"]
            game_info[config.json_key_store_appname] = appslug
            game_info[config.json_key_store_appurl] = self.GetLatestUrl(appslug)
        if "title" in gog_json:
            game_info[config.json_key_store_name] = gog_json["title"].strip()
        if "downloads" in gog_json:
            appdownloads = gog_json["downloads"]
            if "installers" in appdownloads:
                appinstallers = appdownloads["installers"]
                for appinstaller in appinstallers:
                    if appinstaller["os"] == self.GetPreferredPlatform():
                        if appinstaller["version"]:
                            game_info[config.json_key_store_buildid] = appinstaller["version"]
                        else:
                            game_info[config.json_key_store_buildid] = "original_release"
        if "links" in gog_json:
            applinks = gog_json["links"]
            if "product_card" in applinks:
                appurl = applinks["product_card"]
                if appurl and network.IsUrlReachable(appurl):
                    game_info[config.json_key_store_appurl] = applinks["product_card"]

        # Augment by manifest
        if self.manifest:
            manifest_entry = self.manifest.find_entry_by_gogid(
                gogid = identifier,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if manifest_entry:

                # Get existing paths and keys
                game_paths = set(game_info[config.json_key_store_paths])
                game_keys = set(game_info[config.json_key_store_keys])

                # Update paths and keys
                game_paths = game_paths.union(manifest_entry.get_paths(config.token_game_install_dir))
                game_keys = game_keys.union(manifest_entry.get_keys())

                # Save paths and keys
                game_info[config.json_key_store_paths] = system.SortStrings(game_paths)
                game_info[config.json_key_store_keys] = system.SortStrings(game_keys)

        # Return game info
        return jsondata.JsonData(game_info, self.GetPlatform())

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

        # Connect to web
        web_driver = self.WebConnect(
            headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Load url
        success = webpage.LoadUrl(web_driver, identifier)
        if not success:
            return None

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()

        # Look for game description
        element_game_description = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "description"}),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if element_game_description:
            raw_game_description = webpage.GetElementChildrenText(element_game_description)
            if raw_game_description:
                metadata_entry.set_description(raw_game_description)

        # Look for game details
        elements_details = webpage.GetElement(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "details__row"}),
            all_elements = True)
        if elements_details:
            for elements_detail in elements_details:
                element_detail_text = webpage.GetElementChildrenText(elements_detail).strip()

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

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Return metadata entry
        return metadata_entry

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

        # Video
        if asset_type == config.AssetType.VIDEO:
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

    # Install by identifier
    def InstallByIdentifier(
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
        code = command.RunBlockingCommand(
            cmd = install_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return (code != 0)

    ############################################################
    # Launch
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
    # Download
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
        code = command.RunBlockingCommand(
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
