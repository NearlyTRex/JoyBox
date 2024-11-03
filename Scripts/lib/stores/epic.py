# Imports
import os, os.path
import sys
import json

# Local imports
import config
import command
import archive
import programs
import system
import ini
import jsondata
import webpage
import storebase
import metadataentry

# Epic store
class Epic(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

        # Get user details
        self.username = ini.GetIniValue("UserData.Epic", "epic_username")
        if not self.username:
            raise RuntimeError("Ini file does not have a valid epic user details")

        # Get install dir
        self.install_dir = ini.GetIniPathValue("UserData.Epic", "epic_install_dir")
        if not system.IsPathValid(self.install_dir) or not system.DoesPathExist(self.install_dir):
            raise RuntimeError("Ini file does not have a valid epic install dir")

    # Get name
    def GetName(self):
        return "Epic"

    # Get type
    def GetType(self):
        return config.store_type_epic

    # Get platform
    def GetPlatform(self):
        return config.platform_computer_epic_games

    # Get category
    def GetCategory(self):
        return config.game_category_computer

    # Get subcategory
    def GetSubcategory(self):
        return config.game_subcategory_epic_games

    # Get key
    def GetKey(self):
        return config.json_key_epic

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        if identifier_type == config.store_identifier_type_metadata:
            return json_wrapper.get_value(config.json_key_store_appurl)
        return json_wrapper.get_value(config.json_key_store_appname)

    # Get user name
    def GetUserName(self):
        return self.username

    # Get install dir
    def GetInstallDir(self):
        return self.install_dir

    ############################################################

    # Login
    def Login(
        self,
        verbose = False,
        exit_on_failure = False):

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return False

        # Get script
        legendary_script = None
        if programs.IsToolInstalled("Legendary"):
            legendary_script = programs.GetToolProgram("Legendary")
        if not legendary_script:
            system.LogError("Legendary was not found")
            return False

        # Get login command
        login_cmd = [
            python_tool,
            legendary_script,
            "auth"
        ]

        # Run login command
        code = command.RunBlockingCommand(
            cmd = login_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return False

        # Log into website
        success = webpage.LogIntoWebsite(
            driver = web_driver,
            login_url = "https://www.epicgames.com/id/login",
            cookiefile = self.GetCookieFile(),
            class_name = "dropdown--account",
            verbose = verbose)
        if not success:
            return None

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################

    # Get purchases
    def GetPurchases(
        self,
        verbose = False,
        exit_on_failure = False):

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return None

        # Get script
        legendary_script = None
        if programs.IsToolInstalled("Legendary"):
            legendary_script = programs.GetToolProgram("Legendary")
        if not legendary_script:
            system.LogError("Legendary was not found")
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
            system.LogError("Unable to find epic purchases")
            return None

        # Get epic json
        epic_json = []
        try:
            epic_json = json.loads(list_output)
        except Exception as e:
            system.LogError(e)
            system.LogError("Unable to parse epic game list")
            system.LogError("Received output:\n%s" % info_output)
            return None

        # Parse output
        purchases = []
        for entry in epic_json:

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.GetPlatform())
            if "app_name" in entry:
                purchase.set_value(config.json_key_store_appname, entry["app_name"])
            if "app_title" in entry:
                purchase.set_value(config.json_key_store_name, entry["app_title"])
            if "asset_infos" in entry:
                appassets = entry["asset_infos"]
                if "Windows" in appassets:
                    appassetswindows = appassets["Windows"]
                    if "build_version" in appassetswindows:
                        purchase.set_value(config.json_key_store_buildid, appassetswindows["build_version"])
            purchases.append(purchase)
        return purchases

    ############################################################

    # Get latest jsondata
    def GetLatestJsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        exit_on_failure = False):

        # Check identifier
        if not identifier:
            return None

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return None

        # Get script
        legendary_script = None
        if programs.IsToolInstalled("Legendary"):
            legendary_script = programs.GetToolProgram("Legendary")
        if not legendary_script:
            system.LogError("Legendary was not found")
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
            system.LogError("Unable to find epic information for '%s'" % identifier)
            return None

        # Get epic json
        epic_json = {}
        try:
            epic_json = json.loads(info_output)
        except Exception as e:
            system.LogError(e)
            system.LogError("Unable to parse epic game info")
            system.LogError("Received output:\n%s" % info_output)
            return None

        # Build game info
        game_info = {}
        game_info[config.json_key_store_appname] = identifier

        # Augment by json
        if "game" in epic_json:
            appgame = epic_json["game"]
            if "title" in appgame:
                game_info[config.json_key_store_name] = appgame["title"].strip()
            if "version" in appgame:
                game_info[config.json_key_store_buildid] = appgame["version"].strip()
            if "cloud_save_folder" in appgame:
                base_path = None
                if config.json_key_store_installdir in game_info:
                    base_path = game_info[config.json_key_store_installdir]
                game_info[config.json_key_store_paths] = [
                    storebase.TranslateStorePath(appgame["cloud_save_folder"].strip(), base_path)
                ]

        # Return game info
        return jsondata.JsonData(game_info, self.GetPlatform())

    ############################################################

    # Get latest metadata
    def GetLatestMetadata(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):

        # Check identifier
        if not isinstance(identifier, str):
            return None

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Load url
        success = webpage.LoadUrl(web_driver, identifier)
        if not success:
            return None

        # Load cookie
        success = webpage.LoadCookie(web_driver, self.GetCookieFile())
        if not success:
            return None

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()
        metadata_entry.set_url(identifier)

        # Look for game description
        element_game_description = webpage.WaitForPageElement(web_driver, id = "about-long-description", verbose = verbose)
        if element_game_description:
            raw_game_description = webpage.GetElementChildrenText(element_game_description)
            if raw_game_description:
                metadata_entry.set_description(raw_game_description)

        # Look for game genres
        elements_potential_genres = webpage.GetElement(web_driver, class_name = "css-8f0505", all_elements = True)
        if elements_potential_genres:
            for element_potential_genre in elements_potential_genres:
                potential_text = webpage.GetElementChildrenText(element_potential_genre)
                if "Genres" in potential_text:
                    element_game_genres = webpage.GetElement(element_potential_genre, class_name = "css-cyjj8t", all_elements = True)
                    if element_game_genres:
                        game_genres = []
                        for element_game_genre in element_game_genres:
                            game_genre_text = webpage.GetElementChildrenText(element_game_genre)
                            if game_genre_text:
                                game_genres.append(game_genre_text)
                        metadata_entry.set_genre(";".join(game_genres))

        # Look for game details
        elements_details = webpage.GetElement(web_driver, class_name = "css-s97i32", all_elements = True)
        if elements_details:
            for elements_detail in elements_details:
                element_detail_text = webpage.GetElementChildrenText(elements_detail)

                # Developer
                if system.DoesStringStartWithSubstring(element_detail_text, "Developer"):
                    developer_text = system.TrimSubstringFromStart(element_detail_text, "Developer").strip()
                    metadata_entry.set_developer(developer_text)

                # Publisher
                elif system.DoesStringStartWithSubstring(element_detail_text, "Publisher"):
                    published_text = system.TrimSubstringFromStart(element_detail_text, "Publisher").strip()
                    metadata_entry.set_publisher(published_text)

                # Release
                elif system.DoesStringStartWithSubstring(element_detail_text, "Release Date"):
                    release_text = system.TrimSubstringFromStart(element_detail_text, "Release Date").strip()
                    release_text = system.ConvertDateString(release_text, "%m/%d/%y", "%Y-%m-%d")
                    metadata_entry.set_release(release_text)

        # Disconnect from web
        success = self.WebDisconnect(
            web_driver = web_driver,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return None

        # Return metadata entry
        return metadata_entry

    ############################################################

    # Get latest url
    def GetLatestUrl(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):

        # Check identifier
        if not isinstance(identifier, str):
            return None

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Get keywords name
        keywords_name = system.EncodeUrlString(identifier.strip(), use_plus = True)

        # Load url
        success = webpage.LoadUrl(web_driver, "https://store.epicgames.com/en-US/browse?sortBy=releaseDate&sortDir=DESC&q=" + keywords_name)
        if not success:
            return None

        # Find the root container element
        element_search_result = webpage.WaitForPageElement(web_driver, class_name = "css-1ufzxyu", wait_time = 5, verbose = verbose)
        if not element_search_result:
            return None

        # Score each potential title compared to the original title
        scores_list = []
        game_cells = webpage.GetElement(element_search_result, class_name = "css-2mlzob", all_elements = True)
        if game_cells:
            for game_card in game_cells:
                game_title_element = webpage.GetElement(game_card, class_name = "css-rgqwpc", verbose = verbose)
                game_card_text = webpage.GetElementText(game_title_element)

                # Add comparison score
                score_entry = {}
                score_entry["element"] = game_card
                score_entry["ratio"] = system.GetStringSimilarityRatio(identifier, game_card_text)
                scores_list.append(score_entry)

        # Get the best url match
        appurl = None
        for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
            game_card = score_entry["element"]
            game_link_element = webpage.GetElement(game_card, class_name = "css-g3jcms", verbose = verbose)
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

    # Get game save paths
    def GetGameSavePaths(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):
        return []

    ############################################################

    # Install by identifier
    def InstallByIdentifier(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):
        return False

    ############################################################

    # Launch by identifier
    def LaunchByIdentifier(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):
        return False

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
        exit_on_failure = False):
        return False

    ############################################################
