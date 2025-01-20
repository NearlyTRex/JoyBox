# Imports
import os, os.path
import sys

# Local imports
import config
import system
import gameinfo
import google
import stores

############################################################

# Find metadata assets from google images
def FindMetadataAssetsFromGoogleImages(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow BoxFront
    if asset_type != config.AssetType.BOXFRONT:
        return []

    # Return search results
    return google.FindImages(
        search_name = gameinfo.DeriveRegularNameFromGameName(game_name),
        image_dimensions = config.asset_boxfront_dimensions,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Find metadata asset from YouTube
def FindMetadataAssetsFromYouTube(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow Video
    if asset_type != config.AssetType.VIDEO:
        return []

    # Return search results
    return google.FindVideos(
        search_name = gameinfo.DeriveRegularNameFromGameName(game_name, custom_suffix = " trailer"),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Find metadata assets from Steam
def FindMetadataAssetsFromSteam(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow BoxFront and Video
    if asset_type not in [config.AssetType.BOXFRONT, config.AssetType.VIDEO]:
        return []

    # Build asset list
    return stores.FindSteamAssets(
        search_name = gameinfo.DeriveRegularNameFromGameName(game_name),
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Find metadata assets from SteamGridDB
def FindMetadataAssetsFromSteamGridDB(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow BoxFront
    if asset_type != config.AssetType.BOXFRONT:
        return []

    # Return search results
    return stores.FindSteamGridDBCovers(
        search_name = gameinfo.DeriveRegularNameFromGameName(game_name),
        image_dimensions = config.asset_boxfront_dimensions,
        image_types = config.ImageFileType.members(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Find metadata asset
def FindMetadataAsset(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Search results
    search_results = []

    # Try searching Google Images
    search_results += FindMetadataAssetsFromGoogleImages(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Try searching YouTube
    search_results += FindMetadataAssetsFromYouTube(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Try searching Steam
    search_results += FindMetadataAssetsFromSteam(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Try searching SteamGridDB
    search_results += FindMetadataAssetsFromSteamGridDB(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Show possible assets to the user
    system.LogInfo(f"Here are the results for \"{game_name}\"")
    for index, search_result in enumerate(search_results):
        system.LogInfo(f"{index}) {search_result.get_description()} - {search_result.get_url()}")

    # Ask them which one they want to use
    value = system.PromptForValue("Which do you want to use? [Enter an index or type a url to use that]")
    if not value:
        return None

    # Get asset link
    asset_link = None
    if value.startswith("http"):
        asset_link = value
    elif value.isdigit():
        try:
            asset_link = search_results[int(value)].get_url()
        except:
            pass

    # Return metadata
    return asset_link

############################################################
