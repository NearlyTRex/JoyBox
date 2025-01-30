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
import google
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
                system.LogInfo("Collecting metadata for %s - %s ..." % (game_platform, game_name))
            game_entry = metadata_obj.get_game(game_platform, game_name)

            # Collect metadata
            metadata_result = None
            if metadata_source == config.MetadataSourceType.THEGAMESDB:
                metadata_result = CollectMetadataFromTGDB(
                    game_platform = game_platform,
                    game_name = game_name,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            elif metadata_source == config.MetadataSourceType.GAMEFAQS:
                metadata_result = CollectMetadataFromGameFAQS(
                    game_platform = game_platform,
                    game_name = game_name,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            elif metadata_source == config.MetadataSourceType.STORE:
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
                system.LogInfo("Waiting to get next entry ...")
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get metadata platform
    metadata_platform = gameinfo.DeriveGamePlatformFromCategories(metadata_category, metadata_subcategory)

    # Get metadata source
    metadata_source = config.MetadataSourceType.GAMEFAQS
    if stores.GetStoreByPlatform(metadata_platform):
        metadata_source = config.MetadataSourceType.STORE

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
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Collect metadata from TheGamesDB
def CollectMetadataFromTGDB(
    game_platform,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create web driver
    web_driver = webpage.CreateWebDriver(make_headless = True)

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Load url
    success = webpage.LoadUrl(web_driver, "https://thegamesdb.net/search.php?name=" + search_terms)
    if not success:
        return None

    # Get natural name
    natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)

    # Find the root container element
    element_search_result = webpage.WaitForElement(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "container-fluid"}),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not element_search_result:
        return None

    # Score each potential title compared to the original title
    scores_list = []
    game_cells = webpage.GetElement(
        parent = element_search_result,
        locator = webpage.ElementLocator({"class": "card-footer"}),
        all_elements = True)
    if game_cells:
        for game_cell in game_cells:

            # Get possible title
            game_cell_text = webpage.GetElementText(game_cell)
            potential_title = ""
            if game_cell_text:
                for game_cell_text_token in game_cell_text.split("\n"):
                    potential_title = game_cell_text_token
                    break

            # Add comparison score
            score_entry = {}
            score_entry["element"] = game_cell
            score_entry["ratio"] = system.GetStringSimilarityRatio(natural_name, potential_title)
            scores_list.append(score_entry)

    # Click on the highest score element
    for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
        webpage.ClickElement(score_entry["element"])
        break

    # Check if the url has changed
    if webpage.IsUrlLoaded(web_driver, "https://thegamesdb.net/search.php?name="):
        return None

    # Look for game description
    element_game_description = webpage.WaitForElement(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "game-overview"}),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not element_game_description:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(element_game_description)

    # Convert description to metadata format
    if raw_game_description:
        metadata_result.set_description(raw_game_description)

    # Look for game details
    for element_game_details in webpage.GetElement(
        parent = web_driver,
        locator = webpage.ElementLocator({"class": "card-body"}),
        all_elements = True):
        for element_paragraph in webpage.GetElement(
            parent = element_game_details,
            locator = webpage.ElementLocator({"tag": "p"}),
            all_elements = True):
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create web driver
    web_driver = webpage.CreateWebDriver(make_headless = True)

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Load homepage
    success = webpage.LoadUrl(web_driver, "https://gamefaqs.gamespot.com")
    if not success:
        return None

    # Look for homepage marker
    element_homepage_marker = webpage.WaitForElement(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "home_jbi_ft"}),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not element_homepage_marker:
        return None

    # Load url
    success = webpage.LoadUrl(web_driver, "https://gamefaqs.gamespot.com/search_advanced?game=" + search_terms)
    if not success:
        return None

    # Look for search results
    element_search_result = webpage.WaitForElement(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "span12"}),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not element_search_result:
        return None

    # Look for search table
    elements_search_table = webpage.GetElement(
        parent = element_search_result,
        locator = webpage.ElementLocator({"tag": "tbody"}))
    if elements_search_table:

        # Look for search rows
        elements_search_rows = webpage.GetElement(
            parent = elements_search_table,
            locator = webpage.ElementLocator({"tag": "tr"}),
            all_elements = True)
        if elements_search_rows:
            for elements_search_row in elements_search_rows:

                # Examine columns
                elements_search_cols = webpage.GetElement(
                    parent = elements_search_row,
                    locator = webpage.ElementLocator({"tag": "td"}),
                    all_elements = True)
                if elements_search_cols and len(elements_search_cols) >= 4:
                    search_platform = elements_search_cols[0]
                    search_game = elements_search_cols[1]
                    search_game_platform = webpage.GetElementChildrenText(search_platform)
                    search_game_name = webpage.GetElementChildrenText(search_game)
                    search_game_link = webpage.GetElementLinkUrl(search_game)
                    if not search_game_platform or not search_game_name or not search_game_link:
                        continue

                    # Navigate to the entry if this matches the search terms
                    if search_game_platform == config.gamefaqs_platforms[game_platform][0]:
                        webpage.LoadUrl(web_driver, search_game_link)
                        break

    # Look for game description
    element_game_description = webpage.WaitForElement(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "game_desc"}),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not element_game_description:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(element_game_description)

    # Click the "more" button if it's present
    if "more »" in raw_game_description:
        element_game_description_more = webpage.GetElement(
            parent = web_driver,
            locator = webpage.ElementLocator({"link_text": "more »"}))
        if element_game_description_more:
            webpage.ClickElement(element_game_description_more)

    # Re-grab the description text
    raw_game_description = webpage.GetElementText(element_game_description)

    # Convert description to metadata format
    if isinstance(raw_game_description, str):
        metadata_result.set_description(raw_game_description)

    # Look for game details
    for element_game_details in webpage.GetElement(
        parent = web_driver,
        locator = webpage.ElementLocator({"class": "content"}),
        all_elements = True):
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

# Collect metadata from BigFishGames
def CollectMetadataFromBigFishGames(
    game_platform,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create web driver
    web_driver = webpage.CreateWebDriver(make_headless = True)

    # Get search terms
    search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Load url
    success = webpage.LoadUrl(web_driver, "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=" + search_terms)
    if not success:
        return None

    # Look for game description
    element_game_description = webpage.WaitForElement(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "productFullDetail__descriptionContent"}),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not element_game_description:
        return None

    # Look for game bullets
    element_game_bullets = webpage.WaitForElement(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "productFullDetail__bullets"}),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not element_game_bullets:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(element_game_description)

    # Grab the bullets text
    raw_game_bullets = webpage.GetElementText(element_game_bullets)

    # Convert both to metadata format
    if isinstance(raw_game_description, str) and isinstance(raw_game_bullets, str):
        metadata_result.set_description(raw_game_description + "\n" + raw_game_bullets)

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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Try from GameFAQs
    metadata_result_gamefaqs = CollectMetadataFromGameFAQS(
        game_platform = game_platform,
        game_name = game_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if isinstance(metadata_result_gamefaqs, metadataentry.MetadataEntry):
        metadata_result.merge(metadata_result_gamefaqs)

    # Return result
    return metadata_result

############################################################
