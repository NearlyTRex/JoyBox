# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import saves
import gameinfo
import jsondata
import collection
from tools import ludusavimanifest

# Translate store path
def TranslateStorePath(path, base_path = None):

    # Replace tokens
    new_path = path
    new_path = new_path.replace("{EpicID}", "<storeUserId>")
    new_path = new_path.replace("{EpicId}", "<storeUserId>")
    new_path = new_path.replace("{UserDir}", "<home>")
    new_path = new_path.replace("{InstallDir}", "<base>")
    new_path = new_path.replace("{UserSavedGames}", "<home>/Saved Games")
    new_path = new_path.replace("{AppData}/../Roaming", "<winAppData>")
    new_path = new_path.replace("{AppData}/../Roaming".lower(), "<winAppData>")
    new_path = new_path.replace("{AppData}/../LocalLow", "<winAppDataLocalLow>")
    new_path = new_path.replace("{AppData}/../LocalLow".lower(), "<winAppDataLocalLow>")
    new_path = new_path.replace("{AppData}", "<winLocalAppData>")
    new_path = new_path.replace("<storeUserId>", config.token_store_user_id)
    new_path = new_path.replace("<winPublic>", config.token_user_public_dir)
    new_path = new_path.replace("<winDir>", "%s/AppData/Local/VirtualStore" % config.token_user_profile_dir)
    new_path = new_path.replace("<winAppData>", "%s/AppData/Roaming" % config.token_user_profile_dir)
    new_path = new_path.replace("<winAppDataLocalLow>", "%s/AppData/LocalLow" % config.token_user_profile_dir)
    new_path = new_path.replace("<winLocalAppData>", "%s/AppData/Local" % config.token_user_profile_dir)
    new_path = new_path.replace("<winProgramData>", "%s/AppData/Local/VirtualStore" % config.token_user_profile_dir)
    new_path = new_path.replace("<winDocuments>", "%s/Documents" % config.token_user_profile_dir)
    new_path = new_path.replace("<home>", config.token_user_profile_dir)
    new_path = new_path.replace("<root>", config.token_store_install_dir)
    if system.IsPathValid(base_path):
        new_path = new_path.replace("<base>", "%s/%s" % (config.token_store_install_dir, base_path))
    else:
        new_path = new_path.replace("<base>", config.token_store_install_dir)

    # Replace wildcards
    if "/**/" in new_path:
        for new_path_part in new_path.split("/**/"):
            new_path = new_path_part
            break
    if "*" in system.GetFilenameFile(new_path):
        new_path = system.GetFilenameDirectory(new_path)

    # Return path
    return system.NormalizeFilePath(new_path)

# Base store
class StoreBase:

    # Constructor
    def __init__(self):
        self.manifest = None

    # Get name
    def GetName(self):
        return ""

    # Get platform
    def GetPlatform(self):
        return ""

    # Get category
    def GetCategory(self):
        return ""

    # Get subcategory
    def GetSubcategory(self):
        return ""

    # Get key
    def GetKey(self):
        return ""

    # Get identifier
    def GetIdentifier(self, game_info, identifier_type):
        return ""

    # Get info identifier
    def GetInfoIdentifier(self, game_info):
        return self.GetIdentifier(game_info, config.store_identifier_type_info)

    # Get install identifier
    def GetInstallIdentifier(self, game_info):
        return self.GetIdentifier(game_info, config.store_identifier_type_install)

    # Get launch identifier
    def GetLaunchIdentifier(self, game_info):
        return self.GetIdentifier(game_info, config.store_identifier_type_launch)

    # Get download identifier
    def GetDownloadIdentifier(self, game_info):
        return self.GetIdentifier(game_info, config.store_identifier_type_download)

    # Is valid identifier
    def IsValidIdentifier(self, identifier):
        return isinstance(identifier, str) and len(identifier)

    ############################################################

    # Load manifest
    def LoadManifest(self, verbose = False, exit_on_failure = False):
        self.manifest = system.ReadYamlFile(
            src = ludusavimanifest.GetManifest(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    ############################################################

    # Login
    def Login(
        self,
        verbose = False,
        exit_on_failure = False):
        return False

    ############################################################

    # Get purchases
    def GetPurchases(
        self,
        verbose = False,
        exit_on_failure = False):
        return []

    # Display purchases
    def DisplayPurchases(
        self,
        verbose = False,
        exit_on_failure = False):
        return False

    # Import purchases
    def ImportPurchases(
        self,
        verbose = False,
        exit_on_failure = False):

        # Get all purchases
        purchases = self.GetPurchases(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not purchases:
            return False

        # Get all ignores
        ignores = collection.GetGameJsonIgnoreEntries(
            game_category = self.GetCategory(),
            game_subcategory = self.GetSubcategory(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Import each purchase
        for purchase in purchases:
            purchase_appid = purchase.GetJsonValue(config.json_key_store_appid)
            purchase_appname = purchase.GetJsonValue(config.json_key_store_appname)
            purchase_appurl = purchase.GetJsonValue(config.json_key_store_appurl)
            purchase_name = purchase.GetJsonValue(config.json_key_store_name)
            purchase_identifiers = [
                purchase_appid,
                purchase_appname,
                purchase_appurl
            ]

            # Get primary identifier
            primary_identifier = None
            for purchase_identifier in purchase_identifiers:
                if purchase_identifier:
                    primary_identifier = purchase_identifier
            if not primary_identifier:
                continue

            # Check if json file already exists
            found_file = self.FindJsonByIdentifiers(
                identifiers = purchase_identifiers,
                verbose = False,
                exit_on_failure = exit_on_failure)
            if found_file:
                continue

            # Check if this should be ignored
            if primary_identifier in ignores.keys():
                continue

            # Determine if this should be imported
            system.Log("Found new potential entry:")
            if purchase_appid:
                system.Log(" - Appid:\t" + purchase_appid)
            if purchase_appname:
                system.Log(" - Appname:\t" + purchase_appname)
            if purchase_appurl:
                system.Log(" - Appurl:\t" + purchase_appurl)
            if purchase_name:
                system.Log(" - Name:\t" + purchase_name)
            should_import = system.PromptForValue("Import this? (n to skip, i to ignore)", default_value = "n")
            if should_import.lower() == "n":
                continue

            # Add to ignore
            if should_import.lower() == "i":
                collection.AddGameJsonIgnoreEntry(
                    game_category = self.GetCategory(),
                    game_subcategory = self.GetSubcategory(),
                    game_identifier = primary_identifier,
                    game_name = purchase_name,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                continue

            # Prompt for entry name
            default_name = gameinfo.DeriveGameNameFromRegularName(purchase_name)
            entry_name = system.PromptForValue("Choose entry name", default_value = default_name)

            # Create store data
            store_data = {}
            for json_key in config.json_keys_store_subdata:
                if purchase.GetJsonValue(json_key):
                    store_data[json_key] = purchase.GetJsonValue(json_key)

            # Create initial json data
            initial_data = {}
            initial_data[self.GetKey()] = store_data

            # Create json file
            success = collection.CreateGameJsonFile(
                game_category = self.GetCategory(),
                game_subcategory = self.GetSubcategory(),
                game_title = entry_name,
                initial_data = initial_data,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

            # Add metadata entry
            success = collection.AddMetadataEntry(
                game_category = self.GetCategory(),
                game_subcategory = self.GetSubcategory(),
                game_name = entry_name,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

        # Should be successful
        return True

    ############################################################

    # Get latest info
    def GetLatestInfo(
        self,
        identifier,
        branch = None,
        verbose = False,
        exit_on_failure = False):
        return {}

    ############################################################

    # Get save paths
    def GetSavePaths(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):
        return []

    ############################################################

    # Get versions
    def GetVersions(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Get latest info
        latest_info = self.GetLatestInfo(
            identifier = self.GetInfoIdentifier(game_info),
            branch = game_info.get_store_branchid(self.GetKey()),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Return versions
        local_version = game_info.get_store_buildid(self.GetKey())
        remote_version = latest_info[config.json_key_store_buildid]
        return (local_version, remote_version)

    ############################################################

    # Install game by identifier
    def InstallByIdentifier(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):
        return False

    # Install by game info
    def InstallByGameInfo(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Install game
        return self.InstallByIdentifier(
            identifier = self.GetInstallIdentifier(game_info),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    ############################################################

    # Launch by identifier
    def LaunchByIdentifier(
        self,
        identifier,
        verbose = False,
        exit_on_failure = False):
        return False

    # Launch by game info
    def LaunchByGameInfo(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Launch game
        return self.LaunchByIdentifier(
            identifier = self.GetLaunchIdentifier(game_info),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

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

    # Download by game info
    def DownloadByGameInfo(
        self,
        game_info,
        output_dir = None,
        skip_existing = False,
        force = False,
        verbose = False,
        exit_on_failure = False):

        # Get output dir
        if output_dir:
            output_offset = environment.GetLockerGamingRomDirOffset(
                rom_category = game_info.get_category(),
                rom_subcategory = game_info.get_subcategory(),
                rom_name = game_info.get_name())
            output_dir = os.path.join(os.path.realpath(output_dir), output_offset)
        else:
            output_dir = environment.GetLockerGamingRomDir(
                rom_category = game_info.get_category(),
                rom_subcategory = game_info.get_subcategory(),
                rom_name = game_info.get_name())
        if skip_existing and system.DoesDirectoryContainFiles(output_dir):
            return True

        # Get versions
        local_version, remote_version = self.GetVersions(
            game_info = game_info,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Check if game should be downloaded
        should_download = False
        if force or local_version is None or remote_version is None:
            should_download = True
        elif len(local_version) == 0:
            should_download = True
        elif len(local_version) > 0 and len(remote_version) == 0:
            should_download = True
        else:
            if remote_version.isnumeric() and local_version.isnumeric():
                should_download = int(remote_version) > int(local_version)
            else:
                should_download = remote_version != local_version
        if not should_download:
            return True

        # Download game
        success = self.DownloadByIdentifier(
            identifier = self.GetDownloadIdentifier(game_info),
            branch = game_info.get_store_branchid(self.GetKey()),
            output_dir = output_dir,
            output_name = "%s (%s)" % (game_info.get_name(), remote_version),
            clean_output = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################

    # Find json by identifiers
    def FindJsonByIdentifiers(
        self,
        identifiers,
        verbose = False,
        exit_on_failure = False):
        json_files = system.BuildFileListByExtensions(
            root = environment.GetJsonRomMetadataDir(self.GetCategory(), self.GetSubcategory()),
            extensions = [".json"])
        for json_file in json_files:
            json_data = system.ReadJsonFile(
                src = json_file,
                exit_on_failure = exit_on_failure)
            if self.GetKey() not in json_data:
                continue
            json_store_data = json_data[self.GetKey()]
            for appdata_key in config.json_keys_store_appdata:
                if appdata_key not in json_store_data:
                    continue
                for identifier in identifiers:
                    if identifier and identifier == json_store_data[appdata_key]:
                        return json_file
        return None

    ############################################################

    # Update json
    def UpdateJson(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Get latest info
        latest_info = self.GetLatestInfo(
            identifier = self.GetInfoIdentifier(game_info),
            branch = game_info.get_store_branchid(self.GetKey()),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not latest_info:
            return False

        # Read json file
        json_data = system.ReadJsonFile(
            src = game_info.get_json_file(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not json_data:
            return False

        # Create json data object
        json_obj = jsondata.JsonData(json_data[self.GetKey()], game_info.get_platform())

        # Set store info
        for json_subdata_key in config.json_keys_store_subdata:
            if json_subdata_key in latest_info:
                json_obj.FillJsonValue(json_subdata_key, latest_info[json_subdata_key])

        # Save store info
        json_data[self.GetKey()] = json_obj.GetJsonData()

        # Write json file
        success = system.WriteJsonFile(
            src = game_info.get_json_file(),
            json_data = json_data,
            sort_keys = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################

    # Export save
    def ExportSave(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Copy save files
        at_least_one_copy = False
        for save_path_entry in self.GetGameSavePaths(
            game_info = game_info,
            verbose = verbose,
            exit_on_failure = exit_on_failure):
            path_full = save_path_entry["full"]
            for path_relative in save_path_entry["relative"]:
                if system.DoesDirectoryContainFiles(path_full):
                    success = system.SmartCopy(
                        src = path_full,
                        dest = os.path.join(tmp_dir_result, path_relative),
                        show_progress = True,
                        skip_existing = True,
                        ignore_symlinks = True,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    if success:
                        at_least_one_copy = True
        if not at_least_one_copy:
            system.RemoveDirectory(tmp_dir_result, verbose = verbose)
            return True

        # Pack save
        success = saves.PackSave(
            save_category = game_info.get_category(),
            save_subcategory = game_info.get_subcategory(),
            save_name = game_info.get_name(),
            save_dir = tmp_dir_result,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Delete temporary directory
        system.RemoveDirectory(tmp_dir_result, verbose = verbose)
        return True

    ############################################################

    # Import save
    def ImportSave(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):
        return False

    ############################################################
