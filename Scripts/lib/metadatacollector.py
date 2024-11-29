# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import platforms
import gameinfo
import webpage
import youtube
import metadata
import metadataentry

############################################################

# Collect metadata from file
def CollectMetadataFromFile(
    metadata_file,
    metadata_source,
    keys_to_check = [],
    force_download = False,
    allow_replacing = False,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Skip invalid metadata files
    if not environment.IsMetadataFile(metadata_file):
        return False

    # Open metadata file
    metadata_obj = metadata.Metadata()
    metadata_obj.import_from_metadata_file(metadata_file)

    # Get keys to check
    metadata_keys_to_check = []
    if isinstance(keys_to_check, list) and len(keys_to_check) > 0:
        metadata_keys_to_check = keys_to_check
    else:
        metadata_keys_to_check = config.metadata_keys_downloadable

    # Iterate through each game entry to fill in any missing data
    for game_platform in metadata_obj.get_sorted_platforms():
        for game_name in metadata_obj.get_sorted_names(game_platform):
            if not force_download:
                if not metadata_obj.is_entry_missing_data(game_platform, game_name, metadata_keys_to_check):
                    continue

            # Get entry
            if verbose:
                system.Log("Collecting metadata for %s - %s ..." % (game_platform, game_name))
            game_entry = metadata_obj.get_game(game_platform, game_name)

            # Collect metadata
            metadata_result = None
            if metadata_source == config.metadata_source_type_thegamesdb:
                metadata_result = CollectMetadataFromTGDB(
                    game_platform = game_platform,
                    game_name = game_name,
                    select_automatically = select_automatically,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            elif metadata_source == config.metadata_source_type_gamefaqs:
                metadata_result = CollectMetadataFromGameFAQS(
                    game_platform = game_platform,
                    game_name = game_name,
                    select_automatically = select_automatically,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            elif metadata_source == config.metadata_source_type_store:
                store_obj = stores.GetStoreByPlatform(game_platform)
                if store_obj:
                    metadata_result = store_obj.GetLatestMetadata(
                        identifier = game_entry.get_url(),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

            # Merge in metadata result
            if metadata_result:

                # Update keys
                for metadata_key in metadata_keys_to_check:
                    if not metadata_result.is_key_set(metadata_key):
                        continue
                    if game_entry.is_key_set(metadata_key) and not allow_replacing:
                        continue
                    game_entry.set_value(metadata_key, metadata_result.get_value(metadata_key))

            # Write metadata back to file
            metadata_obj.set_game(game_platform, game_name, game_entry)
            metadata_obj.export_to_metadata_file(metadata_file)

            # Wait
            if verbose:
                system.Log("Waiting to get next entry ...")
            system.SleepProgram(5)

    # Should be successful
    return True

# Collect metadata from directory
def CollectMetadataFromDirectory(
    metadata_dir,
    metadata_source,
    keys_to_check = [],
    force_download = False,
    allow_replacing = False,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Collect missing metadata
    for file in system.BuildFileList(os.path.realpath(metadata_dir)):
        success = CollectMetadataFromFile(
            metadata_file = file,
            metadata_source = metadata_source,
            keys_to_check = keys_to_check,
            force_download = force_download,
            allow_replacing = allow_replacing,
            select_automatically = select_automatically,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Collect metadata from categories
def CollectMetadataFromCategories(
    metadata_category,
    metadata_subcategory,
    keys_to_check = [],
    force_download = False,
    allow_replacing = False,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get metadata platform
    metadata_platform = gameinfo.DeriveGamePlatformFromCategories(metadata_category, metadata_subcategory)

    # Get metadata source
    metadata_source = config.metadata_source_type_thegamesdb
    if stores.GetStoreByPlatform(metadata_platform):
        metadata_source = config.metadata_source_type_store

    # Get metadata file
    metadata_file = environment.GetMetadataFile(metadata_category, metadata_subcategory)
    if not metadata_file:
        return False

    # Collect missing metadata
    return CollectMetadataFromFile(
        metadata_file = metadata_file,
        metadata_source = metadata_source,
        keys_to_check = keys_to_check,
        force_download = force_download,
        allow_replacing = allow_replacing,
        select_automatically = select_automatically,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Collect metadata from TheGamesDB
def CollectMetadataFromTGDB(
    game_platform,
    game_name,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create web driver
    web_driver = webpage.CreateWebDriver()

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Load url
    success = webpage.LoadUrl(web_driver, "https://thegamesdb.net/search.php?name=" + search_terms)
    if not success:
        return None

    # Select an entry automatically
    if select_automatically:

        # Get natural name
        natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)

        # Find the root container element
        element_search_result = webpage.WaitForPageElement(web_driver, class_name = "container-fluid", wait_time = 5, verbose = verbose)
        if not element_search_result:
            return None

        # Score each potential title compared to the original title
        scores_list = []
        game_cards = webpage.GetElement(element_search_result, class_name = "card-footer", all_elements = True)
        if game_cards:
            for game_card in game_cards:
                game_card_text = webpage.GetElementText(game_card)

                # Get potential title
                potential_title = ""
                if game_card_text:
                    for game_card_text_token in game_card_text.split("\n"):
                        potential_title = game_card_text_token
                        break

                # Get comparison score
                score_entry = {}
                score_entry["node"] = game_card
                score_entry["ratio"] = system.GetStringSimilarityRatio(natural_name, potential_title)
                scores_list.append(score_entry)

        # Click on the highest score node
        for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
            webpage.ClickElement(score_entry["node"])
            break

        # Check if the url has changed
        if webpage.IsUrlLoaded(web_driver, "https://thegamesdb.net/search.php?name="):
            return None

    # Look for game description
    element_game_description = webpage.WaitForPageElement(web_driver, class_name = "game-overview", verbose = verbose)
    if not element_game_description:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(element_game_description)

    # Convert description to metadata format
    if raw_game_description:
        metadata_result.set_description(raw_game_description)

    # Look for game details
    for element_game_details in webpage.GetElement(web_driver, class_name = "card-body", all_elements = True):
        for element_paragraph in webpage.GetElement(element_game_details, tag_name = "p", all_elements = True):
            element_text = webpage.GetElementText(element_paragraph)
            if not element_text:
                continue

            # Genre
            if system.DoesStringStartWithSubstring(element_text, "Genre(s):"):
                genre_text = system.TrimSubstringFromStart(element_text, "Genre(s):").replace(" | ", ";").strip()
                metadata_result.set_genre(genre_text)

            # Co-op
            if system.DoesStringStartWithSubstring(element_text, "Co-op:"):
                coop_text = system.TrimSubstringFromStart(element_text, "Co-op:").strip()
                metadata_result.set_coop(coop_text)

            # Developer
            if system.DoesStringStartWithSubstring(element_text, "Developer(s):"):
                developer_text = system.TrimSubstringFromStart(element_text, "Developer(s):").strip()
                metadata_result.set_developer(developer_text)

            # Publisher
            if system.DoesStringStartWithSubstring(element_text, "Publishers(s):"):
                publisher_text = system.TrimSubstringFromStart(element_text, "Publishers(s):").strip()
                metadata_result.set_publisher(publisher_text)

            # Players
            if system.DoesStringStartWithSubstring(element_text, "Players:"):
                players_text = system.TrimSubstringFromStart(element_text, "Players:").strip()
                metadata_result.set_players(players_text)

            # Release
            if system.DoesStringStartWithSubstring(element_text, "ReleaseDate:"):
                release_text = system.TrimSubstringFromStart(element_text, "ReleaseDate:").strip()
                metadata_result.set_release(release_text)

    # Cleanup web driver
    webpage.DestroyWebDriver(web_driver)

    # Return metadata
    return metadata_result

############################################################

# Collect metadata from GameFAQs
def CollectMetadataFromGameFAQS(
    game_platform,
    game_name,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create web driver
    web_driver = webpage.CreateWebDriver()

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Load url
    success = webpage.LoadUrl(web_driver, "https://gamefaqs.gamespot.com/search_advanced?game=" + search_terms)
    if not success:
        return None

    # Look for game description
    element_game_description = webpage.WaitForPageElement(web_driver, class_name = "game_desc", verbose = verbose)
    if not element_game_description:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(element_game_description)

    # Click the "more" button if it's present
    if "more »" in raw_game_description:
        element_game_description_more = webpage.GetElement(web_driver, link_text = "more »")
        if element_game_description_more:
            webpage.ClickElement(element_game_description_more)

    # Re-grab the description text
    raw_game_description = webpage.GetElementText(element_game_description)

    # Convert description to metadata format
    if isinstance(raw_game_description, str):
        metadata_result.set_description(raw_game_description)

    # Look for game details
    for element_game_details in webpage.GetElement(web_driver, class_name = "content", all_elements = True):
        element_text = webpage.GetElementText(element_game_details)
        if not element_text:
            continue

        # Genre
        if system.DoesStringStartWithSubstring(element_text, "Genre:"):
            genre_text = system.TrimSubstringFromStart(element_text, "Genre:").replace(" » ", ";").strip()
            metadata_result.set_genre(genre_text)

        # Developer
        elif system.DoesStringStartWithSubstring(element_text, "Developer:"):
            developer_text = system.TrimSubstringFromStart(element_text, "Developer:").strip()
            metadata_result.set_developer(developer_text)

        # Publisher
        elif system.DoesStringStartWithSubstring(element_text, "Publisher:"):
            publisher_text = system.TrimSubstringFromStart(element_text, "Publisher:").strip()
            metadata_result.set_publisher(publisher_text)

        # Developer/Publisher
        elif system.DoesStringStartWithSubstring(element_text, "Developer/Publisher:"):
            devpub_text = system.TrimSubstringFromStart(element_text, "Developer/Publisher:").strip()
            metadata_result.set_developer(devpub_text)
            metadata_result.set_publisher(devpub_text)

        # Release/First Released
        elif system.DoesStringStartWithSubstring(element_text, "Release:") or system.DoesStringStartWithSubstring(element_text, "First Released:"):
            release_text = ""
            if system.DoesStringStartWithSubstring(element_text, "Release:"):
                release_text = system.TrimSubstringFromStart(element_text, "Release:").strip()
            elif system.DoesStringStartWithSubstring(element_text, "First Released:"):
                release_text = system.TrimSubstringFromStart(element_text, "First Released:").strip()
            release_text = system.ConvertUnknownDateString(release_text, "%Y-%m-%d")
            metadata_result.set_release(release_text)

    # Cleanup web driver
    webpage.DestroyWebDriver(web_driver)

    # Return metadata
    return metadata_result

############################################################

# Collect metadata from all
def CollectMetadataFromAll(
    game_platform,
    game_name,
    keys_to_check,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Try from TheGamesDB
    metadata_result_thegamesdb = CollectMetadataFromTGDB(
        game_platform = game_platform,
        game_name = game_name,
        select_automatically = select_automatically,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if isinstance(metadata_result_thegamesdb, metadataentry.MetadataEntry):
        metadata_result.merge(metadata_result_thegamesdb)

    # Check if done
    if not metadata_result.is_missing_data(keys_to_check):
        return metadata_result

    # Try from GameFAQs
    metadata_result_gamefaqs = CollectMetadataFromGameFAQS(
        game_platform = game_platform,
        game_name = game_name,
        select_automatically = select_automatically,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if isinstance(metadata_result_gamefaqs, metadataentry.MetadataEntry):
        metadata_result.merge(metadata_result_gamefaqs)

    # Return result
    return metadata_result

############################################################

# Collect metadata asset from SteamGridDB
def CollectMetadataAssetFromSteamGridDB(
    game_platform,
    game_name,
    asset_type,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow BoxFront
    if asset_type != config.asset_type_boxfront:
        return None

    # Create web driver
    web_driver = webpage.CreateWebDriver()

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

    # Metadata asset
    metadata_asset = None

    # Load url
    success = webpage.LoadUrl(web_driver, "https://www.steamgriddb.com/search/grids/all/all/all?term=" + search_terms)
    if not success:
        return None

    # Look for asset page
    element_asset_page = webpage.WaitForPageElement(web_driver, class_name = "container-asset-page", verbose = verbose)
    if not element_asset_page:
        return None

    # Look for asset download
    element_asset_download = webpage.WaitForPageElement(web_driver, class_name = "asset-download", verbose = verbose)
    if not element_asset_download:
        return None

    # Get asset link
    element_asset_link = webpage.GetElement(element_asset_download, class_name = "btn", verbose = verbose)
    if element_asset_link:
        metadata_asset = webpage.GetElementAttribute(element_asset_link, "href")

    # Cleanup web driver
    webpage.DestroyWebDriver(web_driver)

    # Return metadata
    return metadata_asset

# Collect metadata asset from YouTube
def CollectMetadataAssetFromYouTube(
    game_platform,
    game_name,
    asset_type,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Only allow Video
    if asset_type != config.asset_type_video:
        return None

    # Metadata asset
    metadata_asset = None

    # Get search results
    search_results = youtube.GetSearchResults(
        search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform, search_terms = ["trailer"]),
        num_results = 20,
        sort_by_duration = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Show search results to the user
    system.Log(f"Here are the search results for \"{game_name}\"")
    for index in range(0, len(search_results)):
        search_result = search_results[index]
        search_title = search_result["title"]
        search_channel = search_result["channel"]
        search_duration = search_result["duration_string"]
        search_url = search_result["url"]
        system.Log(f"{index}) \"{search_title}\" ({search_channel}) [{search_duration}] - {search_url}")

    # Ask them which one they want to use
    value = system.PromptForValue("Which do you want to use? [Enter an index or type a url to use that]")
    if not value:
        return None

    # Get asset link
    if value.startswith("https://www.youtube.com"):
        metadata_asset = value
    elif value.isdigit():
        try:
            metadata_asset = search_results[int(value)]["url"]
        except:
            pass

    # Return metadata
    return metadata_asset

############################################################

# Collect metadata asset from all
def CollectMetadataAssetFromAll(
    game_platform,
    game_name,
    asset_type,
    select_automatically = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Try from SteamGridDB
    metadata_asset = CollectMetadataAssetFromSteamGridDB(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        select_automatically = select_automatically,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if isinstance(metadata_asset, str):
        return metadata_asset

    # Try from YouTube
    metadata_asset = CollectMetadataAssetFromYouTube(
        game_platform = game_platform,
        game_name = game_name,
        asset_type = asset_type,
        select_automatically = select_automatically,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if isinstance(metadata_asset, str):
        return metadata_asset

    # No result
    return None

############################################################
