# Imports
import os, os.path
import sys

# Local imports
import config
import system
import gameinfo
import google
import stores
import metadata

############################################################

# Collect metadata assets from google images
def CollectMetadataAssetsFromGoogleImages(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow BoxFront
    if asset_type != config.AssetType.BOXFRONT:
        return []

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(
        game_name = game_name,
        game_platform = game_platform,
        asset_type = asset_type)

    # Get search results
    search_results = google.FindImages(
        search_terms = search_terms,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Build asset list
    metadata_assets = []
    for search_result in search_results:
        result_title = search_result["title"]
        result_mime = search_result["mime"]
        result_url = search_result["url"]
        new_asset = {}
        new_asset["url"] = result_url
        new_asset["description"] = f"\"{result_title}\" ({result_mime}) - {result_url}"
        metadata_assets.append(new_asset)
    return metadata_assets

############################################################

# Collect metadata asset from YouTube
def CollectMetadataAssetsFromYouTube(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow Video
    if asset_type != config.AssetType.VIDEO:
        return []

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(
        game_name = game_name,
        game_platform = game_platform,
        asset_type = asset_type)

    # Get search results
    search_results = google.FindVideos(
        search_terms = search_terms,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Build asset list
    metadata_assets = []
    for search_result in search_results:
        result_title = search_result["title"]
        result_channel = search_result["channel"]
        result_duration = search_result["duration_string"]
        result_url = search_result["url"]
        new_asset = {}
        new_asset["url"] = result_url
        new_asset["description"] = f"\"{result_title}\" ({result_channel}) [{result_duration}] - {result_url}"
        metadata_assets.append(new_asset)
    return metadata_assets

############################################################

# Collect metadata assets from Steam
def CollectMetadataAssetsFromSteam(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow BoxFront and Video
    if asset_type not in [config.AssetType.BOXFRONT, config.AssetType.VIDEO]:
        return []

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(
        game_name = game_name,
        game_platform = game_platform,
        asset_type = asset_type)

    # Build asset list
    metadata_assets = []
    asset_url = None
    if asset_type == config.AssetType.BOXFRONT:
        asset_url = stores.GetLikelySteamCover(search_terms)
    elif asset_type == config.AssetType.VIDEO:
        asset_url = stores.GetLikelySteamTrailer(
            search_terms = search_terms,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if asset_url:
        new_asset = {}
        new_asset["url"] = asset_url
        new_asset["description"] = f"{result_url}"
        metadata_assets.append(new_asset)
    return metadata_assets

############################################################

# Collect metadata assets from SteamGridDB
def CollectMetadataAssetsFromSteamGridDB(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow BoxFront
    if asset_type != config.AssetType.BOXFRONT:
        return []

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(
        game_name = game_name,
        game_platform = game_platform,
        asset_type = asset_type)

    # Get search results
    search_results = stores.FindSteamGridDBCovers(
        search_terms = search_terms,
        image_dimensions = (600, 900),
        image_types = config.ImageFileType.members(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Build asset list
    metadata_assets = []
    for search_result in search_results:
        result_author = search_result["author"]["name"]
        result_style = search_result["style"]
        result_nsfw = str(search_result["nsfw"])
        result_humor = str(search_result["humor"])
        result_language = search_result["language"]
        result_types = ",".join(search_result["types"])
        result_name = search_result["name"]
        result_id = search_result["id"]
        result_release_date = search_result["release_date"]
        result_url = search_result["url"]
        new_asset = {}
        new_asset["url"] = result_url
        new_asset["description"] = f"{result_url} - ({result_id}) ({result_name}) [{result_release_date}] [{result_style}]"
        metadata_assets.append(new_asset)
    return metadata_assets

############################################################

# Collect metadata asset from all
def CollectMetadataAssetFromAll(
    game_platform,
    game_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Metadata assets
    metadata_assets = []

    # Try from YouTube
    metadata_assets += CollectMetadataAssetsFromYouTube(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Try from Steam
    metadata_assets += CollectMetadataAssetsFromSteam(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Try from SteamGridDB
    metadata_assets += CollectMetadataAssetsFromSteamGridDB(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Try from Google Images
    metadata_assets += CollectMetadataAssetsFromGoogleImages(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Show possible assets to the user
    system.LogInfo(f"Here are the results for \"{game_name}\"")
    for index in range(0, len(metadata_assets)):
        metadata_asset = metadata_assets[index]
        metadata_asset_description = metadata_asset["description"]
        system.LogInfo(f"{index}) \"{metadata_asset_description}\"")

    # Ask them which one they want to use
    value = system.PromptForValue("Which do you want to use? [Enter an index or type a url to use that]")
    if not value:
        return None

    # Get asset link
    if value.startswith("http"):
        metadata_asset = value
    elif value.isdigit():
        try:
            metadata_asset = metadata_assets[int(value)]["url"]
        except:
            pass

    # Return metadata
    return metadata_asset

############################################################
