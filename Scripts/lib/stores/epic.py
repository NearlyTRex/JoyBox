# Imports
import os, os.path
import sys

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
    def GetIdentifier(self, game_info, identifier_type):
        if identifier_type == config.store_identifier_type_metadata:
            return game_info.get_store_appurl(self.GetKey())
        return game_info.get_store_appname(self.GetKey())

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
        return (code == 0)

    # Web connect
    def WebConnect(
        self,
        verbose = False,
        exit_on_failure = False):

        # Create web driver
        try:
            return webpage.CreateWebDriver(verbose = verbose)
        except Exception as e:
            if verbose:
                system.LogError(e)
            return None

    # Web disconnect
    def WebDisconnect(
        self,
        web_driver,
        verbose = False,
        exit_on_failure = False):

        # Destroy web driver
        try:
            webpage.DestroyWebDriver(web_driver, verbose = verbose)
            return True
        except Exception as e:
            if verbose:
                system.LogError(e)
            return False

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
            "list"
        ]

        # Run list command
        list_output = command.RunOutputCommand(
            cmd = list_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if len(list_output) == 0:
            system.LogError("Unable to find epic purchases")
            return None

        # Parse output
        purchases = []
        for line in list_output.split("\n"):

            # Gather info
            line = system.RemoveStringEscapeSequences(line)
            if not line.startswith(" * "):
                continue
            tokens = line.split(" | Version: ")
            if len(tokens) != 2:
                continue
            line = tokens[0]
            line_version = tokens[1].rstrip(")")
            tokens = line.split(" (App name: ")
            if len(tokens) != 2:
                continue
            line = tokens[0]
            line_appname = tokens[1]
            line_title = tokens[0].lstrip(" *")

            # Create purchase
            purchase = jsondata.JsonData(
                json_data = {},
                json_platform = self.GetPlatform())
            purchase.set_value(config.json_key_store_appname, line_appname)
            purchase.set_value(config.json_key_store_buildid, line_version)
            purchase.set_value(config.json_key_store_name, line_title)
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
            "info", identifier
        ]

        # Run info command
        info_output = command.RunOutputCommand(
            cmd = info_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0 or "No game information available" in info_output:
            system.LogError("Unable to find epic information for '%s'" % identifier)
            return None

        # Build game info
        game_info = {}
        game_info[config.json_key_store_appname] = identifier
        for line in info_output.split("\n"):
            if line.startswith("- Title:"):
                game_info[config.json_key_store_name] = line.replace("- Title:", "").strip()
            elif line.startswith("- Latest version:"):
                game_info[config.json_key_store_buildid] = line.replace("- Latest version:", "").strip()
            elif line.startswith("- Cloud save folder (Windows):"):
                line_path = line.replace("- Cloud save folder (Windows):", "").strip()
                if "(None)" not in line_path:
                    base_path = None
                    if config.json_key_store_installdir in game_info:
                        base_path = game_info[config.json_key_store_installdir]
                    game_info[config.json_key_store_paths] = [
                        storebase.TranslateStorePath(line_path, base_path)
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

        # Connect to web
        web_driver = self.WebConnect(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Go to the search page and pull the results
        try:
            web_driver.get(identifier)
        except:
            return None

        # Create metadata entry
        metadata_entry = metadataentry.MetadataEntry()

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
                potential_text = system.ExtractWebText(webpage.GetElementAttribute(element_potential_genre, "innerHTML"))
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
                if element_detail_text.startswith("Developer"):
                    developer_text = element_detail_text.replace("Developer", "").strip()
                    metadata_entry.set_developer(developer_text)
                elif element_detail_text.startswith("Publisher"):
                    published_text = element_detail_text.replace("Publisher", "").strip()
                    metadata_entry.set_publisher(published_text)
                elif element_detail_text.startswith("Release Date"):
                    release_text = element_detail_text.replace("Release Date", "").strip()
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
