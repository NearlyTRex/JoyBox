# Imports
import os, os.path
import sys

# Local imports
import config
import system
import jsondata
from tools import ludusavimanifest

# Base store
class StoreBase:

    # Constructor
    def __init__(self):
        self.manifest = None

    # Get name
    def GetName(self):
        return ""

    # Get key
    def GetKey(self):
        return ""

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

    # Translate manifest path
    def TranslateManifestPath(self, path, base_path = None):

        # Replace tokens
        new_path = path
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
            new_path = new_path.replace("<base>", base_path)

        # Replace wildcards
        if "/**/" in new_path:
            for new_path_part in new_path.split("/**/"):
                new_path = new_path_part
                break
        if "*" in system.GetFilenameFile(new_path):
            new_path = system.GetFilenameDirectory(new_path)

        # Return path
        return new_path

    ############################################################

    # Login
    def Login(
        self,
        verbose = False,
        exit_on_failure = False):
        return False

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

    # Get download identifier
    def GetDownloadIdentifier(self, game_info):
        return ""

    # Get download output name
    def GetDownloadOutputName(self, game_info):
        return ""

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

        # Get game info
        game_appid = game_info.get_store_appid(self.GetKey())
        game_branchid = game_info.get_store_branchid(self.GetKey())
        game_buildid = game_info.get_store_buildid(self.GetKey())

        # Ignore invalid identifier
        if not self.IsValidIdentifier(game_appid):
            return (None, None)

        # Get latest info
        latest_info = self.GetLatestInfo(
            identifier = game_appid,
            branch = game_branchid,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Return versions
        local_version = game_buildid
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

        # Get game info
        game_appid = game_info.get_store_appid(self.GetKey())

        # Ignore invalid identifier
        if not self.IsValidIdentifier(game_appid):
            return True

        # Install game
        return self.InstallByIdentifier(
            identifier = game_appid,
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

        # Get game info
        game_appid = game_info.get_store_appid(self.GetKey())

        # Ignore invalid identifier
        if not self.IsValidIdentifier(game_appid):
            return True

        # Launch game
        return self.LaunchByIdentifier(
            identifier = game_appid,
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

        # Get game info
        game_appid = game_info.get_store_appid(self.GetKey())
        game_branchid = game_info.get_store_branchid(self.GetKey())
        game_category = game_info.get_category()
        game_subcategory = game_info.get_subcategory()
        game_name = game_info.get_name()

        # Ignore invalid identifier
        if not self.IsValidIdentifier(game_appid):
            return True

        # Get output dir
        if output_dir:
            output_offset = environment.GetLockerGamingRomDirOffset(game_category, game_subcategory, game_name)
            output_dir = os.path.join(os.path.realpath(output_dir), output_offset)
        else:
            output_dir = environment.GetLockerGamingRomDir(game_category, game_subcategory, game_name)
        if skip_existing and system.DoesDirectoryContainFiles(output_dir):
            return True

        # Get versions
        local_version, remote_version = self.GetVersions(
            game_info = game_info,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Check if game should be fetched
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
            branch = game_branchid,
            output_dir = output_dir,
            output_name = self.GetDownloadOutputName(game_info),
            clean_output = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################

    # Update json
    def UpdateJson(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_platform = game_info.get_platform()
        game_appid = game_info.get_store_appid(self.GetKey())
        game_branchid = game_info.get_store_branchid(self.GetKey())
        game_json_file = game_info.get_json_file()

        # Ignore invalid identifier
        if not self.IsValidIdentifier(game_appid):
            return True

        # Get latest info
        latest_info = self.GetLatestInfo(
            identifier = game_appid,
            branch = game_branchid,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Read json file
        json_data = system.ReadJsonFile(
            src = game_json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Create json data object
        json_obj = jsondata.JsonData(json_data[self.GetKey()], game_platform)

        # Set store info
        for json_subdata_key in config.json_keys_store_subdata:
            if json_subdata_key in latest_info:
                json_obj.SetJsonValue(json_subdata_key, latest_info[json_subdata_key])

        # Save store info
        json_data[self.GetKey()] = json_obj.GetJsonData()

        # Write json file
        success = system.WriteJsonFile(
            src = game_json_file,
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

        # Get game info
        game_category = game_info.get_category()
        game_subcategory = game_info.get_subcategory()
        game_name = game_info.get_name()

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
                if os.path.exists(path_full):
                    success = system.CopyContents(
                        src = path_full,
                        dest = os.path.join(tmp_dir_result, path_relative),
                        show_progress = True,
                        skip_existing = True,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    if success:
                        at_least_one_copy = True
        if not at_least_one_copy:
            return True

        # Pack save
        success = saves.PackSave(
            save_category = game_category,
            save_subcategory = game_subcategory,
            save_name = game_name,
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
