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
import collection
import gameinfo
import metadata
import stores
import manifest
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Scan roms files.")
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.REMOTE,
    description = "Source type")
parser.add_enum_argument(
    args = ("-t", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker type")
parser.add_string_argument(args = ("-k", "--keys"), description = "Keys to use (comma delimited)")
parser.add_enum_list_argument(args = ("-c", "--categories"), arg_type = config.Category, description = "Categories to process")
parser.add_enum_list_argument(args = ("-s", "--subcategories"), arg_type = config.Subcategory, description = "Subcategories to process")
parser.add_boolean_argument(args = ("-m", "--load_manifest"), description = "Load manifest")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Log filtering if specified
    if args.categories:
        category_names = [c for c in args.categories.split(",")]
        system.LogInfo(f"Filtering to categories: {args.categories}")
    if args.subcategories:
        system.LogInfo(f"Filtering to subcategories: {args.subcategories}")

    # Load manifest
    if args.load_manifest:
        system.LogInfo("Loading manifest ...")
        manifest.GetManifestInstance().load(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Build game store purchases
    system.LogInfo("Building store purchases ...")
    success = collection.BuildAllGameStorePurchases(
        locker_type = args.locker_type,
        source_type = args.source_type,
        categories = args.categories,
        subcategories = args.subcategories,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Building store purchases failed", quit_program = True)

    # Build game json files
    system.LogInfo("Building json files ...")
    success = collection.BuildAllGameJsonFiles(
        locker_type = args.locker_type,
        source_type = args.source_type,
        categories = args.categories,
        subcategories = args.subcategories,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Building json files failed", quit_program = True)

    # Build game metadata files
    system.LogInfo("Building metadata files ...")
    success = collection.BuildAllGameMetadataEntries(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Building metadata files failed", quit_program = True)

    # Download game metadata assets
    system.LogInfo("Downloading metadata assets ...")
    success = collection.DownloadAllMetadataAssets(
        skip_existing = True,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Downloading metadata assets failed", quit_program = True)

    # Publish game metadata files
    system.LogInfo("Publishing metadata files ...")
    success = collection.PublishAllGameMetadataEntries(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        system.LogError("Publishing metadata files failed", quit_program = True)

# Start
if __name__ == "__main__":
    system.RunMain(main)
