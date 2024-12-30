#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import gameinfo
import stores
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Manage store games.")
parser.add_input_path_argument(default = ".")
parser.add_output_path_argument()
parser.add_enum_argument(
    args = ("-t", "--store_type"),
    arg_type = config.StoreType,
    default = config.StoreType.STEAM,
    description = "Store type")
parser.add_enum_argument(
    args = ("-a", "--store_action"),
    arg_type = config.StoreActionType,
    default = config.StoreActionType.LOGIN,
    description = "Store action type")
parser.add_enum_argument(
    args = ("-e", "--asset_type"),
    arg_type = config.AssetType,
    description = "Asset type")
parser.add_boolean_argument(args = ("-s", "--skip_existing"), description = "Skip existing entries")
parser.add_boolean_argument(args = ("-f", "--force"), description = "Always run action")
parser.add_string_argument(args = ("-k", "--keys"), description = "Keys to use (comma delimited)")
parser.add_boolean_argument(args = ("-m", "--load_manifest"), description = "Load manifest")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get store
    store_obj = stores.GetStoreByType(args.store_type)
    if not store_obj:
        system.LogErrorAndQuit("Invalid store")

    # Get input path
    input_path = None
    if system.IsPathValid(args.input_path):
        input_path = parser.get_input_path()
    if not input_path:
        input_path = environment.GetJsonRomMetadataDir(
            game_category = store_obj.GetCategory(),
            game_subcategory = store_obj.GetSubcategory())

    # Load manifest
    if args.load_manifest:
        store_obj.LoadManifest(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Login
    if args.store_action == config.StoreActionType.LOGIN:
        store_obj.Login(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Display purchases
    elif args.store_action == config.StoreActionType.DISPLAY_PURCHASES:
        store_obj.DisplayPurchases(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Import purchases
    elif args.store_action == config.StoreActionType.IMPORT_PURCHASES:
        store_obj.ImportPurchases(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Install game
    elif args.store_action == config.StoreActionType.INSTALL_GAME:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.InstallByGameInfo(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Install of '%s' failed!" % json_file)

    # Launch game
    elif args.store_action == config.StoreActionType.LAUNCH_GAME:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                store_obj.LaunchByGameInfo(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
            break

    # Download game
    elif args.store_action == config.StoreActionType.DOWNLOAD_GAME:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.DownloadByGameInfo(
                    game_info = game_info,
                    output_dir = args.output_path,
                    skip_existing = args.skip_existing,
                    force = args.force,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Download of '%s' failed!" % json_file)

    # Download asset
    elif args.store_action == config.StoreActionType.DOWNLOAD_ASSET:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.DownloadAsset(
                    game_info = game_info,
                    asset_type = args.asset_type,
                    force = args.force,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Download of asset for '%s' failed!" % json_file)

    # Update json
    elif args.store_action == config.StoreActionType.UPDATE_JSON:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.UpdateJson(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Update of '%s' failed!" % json_file)

    # Update metadata
    elif args.store_action == config.StoreActionType.UPDATE_METADATA:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.UpdateMetadata(
                    game_info = game_info,
                    keys = args.keys.split(",") if args.keys else [],
                    force = args.force,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Update of '%s' failed!" % json_file)

    # Check versions
    elif args.store_action == config.StoreActionType.CHECK_VERSIONS:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if game_info and game_info.is_valid():
                local_version, remote_version = store_obj.GetVersions(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if local_version and remote_version:
                    if local_version != remote_version:
                        system.LogWarning("Game '%s' is out of date! Local = '%s', remote = '%s'" % (json_file, local_version, remote_version))

    # Export saves
    elif args.store_action == config.StoreActionType.EXPORT_SAVES:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.ExportSave(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Export of '%s' failed!" % json_file)

    # Import saves
    elif args.store_action == config.StoreActionType.IMPORT_SAVES:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.ImportSave(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Import of '%s' failed!" % json_file)

# Start
main()
