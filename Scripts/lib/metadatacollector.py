# Imports
import os, os.path
import sys

# Local imports
import config
import datautils
import system
import environment
import platforms
import strings
import gameinfo
import webpage
import google
import metadata
import metadataentry

############################################################

# Collect metadata from TheGamesDB
def CollectMetadataFromTGDB(
    game_platform,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Store web driver for cleanup
    web_driver = None

    # Cleanup function
    def cleanup_driver():
        if web_driver:
            webpage.DestroyWebDriver(web_driver)

    # Fetch function
    def attempt_metadata_fetch():
        nonlocal web_driver

        # Create web driver
        web_driver = webpage.CreateWebDriver(make_headless = True)
        if not web_driver:
            raise Exception("Failed to create web driver")

        # Get search terms
        search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

        # Metadata result
        metadata_result = metadataentry.MetadataEntry()

        # Load url
        success = webpage.LoadUrl(web_driver, "https://thegamesdb.net/search.php?name=" + search_terms)
        if not success:
            raise Exception("Failed to load TheGamesDB search page")

        # Get natural name
        natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)

        # Find the root container element
        element_search_result = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "container-fluid"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not element_search_result:
            return None  # No search results found, not an error

        # Score each potential title compared to the original title
        scores_list = []
        game_cells = webpage.GetElement(
            parent = element_search_result,
            locator = webpage.ElementLocator({"class": "card-footer"}),
            all_elements = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
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
                if potential_title:
                    score_entry = {}
                    score_entry["element"] = game_cell
                    score_entry["ratio"] = strings.get_string_similarity_ratio(natural_name, potential_title)
                    scores_list.append(score_entry)

        # Click on the highest score element
        if scores_list:
            for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
                webpage.ClickElement(score_entry["element"])
                break

            # Check if the url has changed
            if webpage.IsUrlLoaded(web_driver, "https://thegamesdb.net/search.php?name="):
                return None  # Still on search page, no valid result found

        # Look for game description
        element_game_description = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "game-overview"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if element_game_description:
            raw_game_description = webpage.GetElementText(element_game_description)
            if raw_game_description and raw_game_description.strip():
                metadata_result.set_description(raw_game_description)

        # Look for game details
        element_game_details_list = webpage.GetElement(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "card-body"}),
            all_elements = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if element_game_details_list:
            for element_game_details in element_game_details_list:
                element_paragraphs = webpage.GetElement(
                    parent = element_game_details,
                    locator = webpage.ElementLocator({"tag": "p"}),
                    all_elements = True,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if element_paragraphs:
                    for element_paragraph in element_paragraphs:
                        element_text = webpage.GetElementText(element_paragraph)
                        if not element_text:
                            continue

                        # Genre
                        if strings.does_string_start_with_substring(element_text, "Genre(s):"):
                            genre_text = strings.trim_substring_from_start(element_text, "Genre(s):").replace(" | ", ";").strip()
                            metadata_result.set_genre(genre_text)

                        # Co-op
                        elif strings.does_string_start_with_substring(element_text, "Co-op:"):
                            coop_text = strings.trim_substring_from_start(element_text, "Co-op:").strip()
                            metadata_result.set_coop(coop_text)

                        # Developer
                        elif strings.does_string_start_with_substring(element_text, "Developer(s):"):
                            developer_text = strings.trim_substring_from_start(element_text, "Developer(s):").strip()
                            metadata_result.set_developer(developer_text)

                        # Publisher
                        elif strings.does_string_start_with_substring(element_text, "Publishers(s):"):
                            publisher_text = strings.trim_substring_from_start(element_text, "Publishers(s):").strip()
                            metadata_result.set_publisher(publisher_text)

                        # Players
                        elif strings.does_string_start_with_substring(element_text, "Players:"):
                            players_text = strings.trim_substring_from_start(element_text, "Players:").strip()
                            metadata_result.set_players(players_text)

                        # Release
                        elif strings.does_string_start_with_substring(element_text, "ReleaseDate:"):
                            release_text = strings.trim_substring_from_start(element_text, "ReleaseDate:").strip()
                            metadata_result.set_release(release_text)
        return metadata_result

    # Use retry function with cleanup
    result = datautils.retry_with_backoff(
        func = attempt_metadata_fetch,
        cleanup_func = cleanup_driver,
        max_retries = 3,
        initial_delay = 2,
        backoff_factor = 2,
        verbose = verbose,
        operation_name = "TheGamesDB metadata fetch for '%s' (%s)" % (game_name, game_platform))

    # Final cleanup
    cleanup_driver()
    return result

############################################################

# Collect metadata from GameFAQs
def CollectMetadataFromGameFAQS(
    game_platform,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Store web driver for cleanup
    web_driver = None

    # Cleanup function
    def cleanup_driver():
        if web_driver:
            webpage.DestroyWebDriver(web_driver)

    # Fetch function
    def attempt_metadata_fetch():
        nonlocal web_driver

        # Create web driver
        web_driver = webpage.CreateWebDriver(make_headless = True)
        if not web_driver:
            raise Exception("Failed to create web driver")

        # Get search terms
        search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

        # Metadata result
        metadata_result = metadataentry.MetadataEntry()

        # Load homepage
        success = webpage.LoadUrl(web_driver, "https://gamefaqs.gamespot.com")
        if not success:
            raise Exception("Failed to load GameFAQs homepage")

        # Look for homepage marker
        element_homepage_marker = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "home_jbi_ft"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not element_homepage_marker:
            raise Exception("GameFAQs homepage marker not found")

        # Load search URL
        success = webpage.LoadUrl(web_driver, "https://gamefaqs.gamespot.com/search_advanced?game=" + search_terms)
        if not success:
            raise Exception("Failed to load GameFAQs search page")

        # Look for search results
        element_search_result = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "span12"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not element_search_result:
            return None  # No search results found, not an error

        # Look for search table
        elements_search_table = webpage.GetElement(
            parent = element_search_result,
            locator = webpage.ElementLocator({"tag": "tbody"}),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if elements_search_table:

            # Look for search rows
            elements_search_rows = webpage.GetElement(
                parent = elements_search_table,
                locator = webpage.ElementLocator({"tag": "tr"}),
                all_elements = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if elements_search_rows:
                for elements_search_row in elements_search_rows:

                    # Examine columns
                    elements_search_cols = webpage.GetElement(
                        parent = elements_search_row,
                        locator = webpage.ElementLocator({"tag": "td"}),
                        all_elements = True,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = False)
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
                            success = webpage.LoadUrl(web_driver, search_game_link)
                            if success:
                                break

        # Look for game description
        element_game_description = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "game_desc"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if element_game_description:

            # Grab the description text
            raw_game_description = webpage.GetElementText(element_game_description)

            # Click the "more" button if it's present
            if raw_game_description and "more »" in raw_game_description:
                element_game_description_more = webpage.GetElement(
                    parent = web_driver,
                    locator = webpage.ElementLocator({"link_text": "more »"}),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if element_game_description_more:
                    webpage.ClickElement(element_game_description_more)
                    raw_game_description = webpage.GetElementText(element_game_description)

            # Convert description to metadata format
            if isinstance(raw_game_description, str) and raw_game_description.strip():
                metadata_result.set_description(raw_game_description)

        # Look for game details
        element_game_details_list = webpage.GetElement(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "content"}),
            all_elements = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if element_game_details_list:
            for element_game_details in element_game_details_list:
                element_text = webpage.GetElementText(element_game_details)
                if not element_text:
                    continue

                # Genre
                if strings.does_string_start_with_substring(element_text, "Genre:"):
                    genre_text = strings.trim_substring_from_start(element_text, "Genre:").replace(" » ", ";").strip()
                    metadata_result.set_genre(genre_text)

                # Developer
                elif strings.does_string_start_with_substring(element_text, "Developer:"):
                    developer_text = strings.trim_substring_from_start(element_text, "Developer:").strip()
                    metadata_result.set_developer(developer_text)

                # Publisher
                elif strings.does_string_start_with_substring(element_text, "Publisher:"):
                    publisher_text = strings.trim_substring_from_start(element_text, "Publisher:").strip()
                    metadata_result.set_publisher(publisher_text)

                # Developer/Publisher
                elif strings.does_string_start_with_substring(element_text, "Developer/Publisher:"):
                    devpub_text = strings.trim_substring_from_start(element_text, "Developer/Publisher:").strip()
                    metadata_result.set_developer(devpub_text)
                    metadata_result.set_publisher(devpub_text)

                # Release/First Released
                elif strings.does_string_start_with_substring(element_text, "Release:") or strings.does_string_start_with_substring(element_text, "First Released:"):
                    release_text = ""
                    if strings.does_string_start_with_substring(element_text, "Release:"):
                        release_text = strings.trim_substring_from_start(element_text, "Release:").strip()
                    elif strings.does_string_start_with_substring(element_text, "First Released:"):
                        release_text = strings.trim_substring_from_start(element_text, "First Released:").strip()
                    release_text = strings.convert_unknown_date_string(release_text, "%Y-%m-%d")
                    metadata_result.set_release(release_text)
        return metadata_result

    # Use retry function with cleanup
    result = datautils.retry_with_backoff(
        func = attempt_metadata_fetch,
        cleanup_func = cleanup_driver,
        max_retries = 3,
        initial_delay = 2,
        backoff_factor = 2,
        verbose = verbose,
        operation_name = "GameFAQs metadata fetch for '%s' (%s)" % (game_name, game_platform))

    # Final cleanup
    cleanup_driver()
    return result

############################################################

# Collect metadata from BigFishGames
def CollectMetadataFromBigFishGames(
    game_platform,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Store web driver for cleanup
    web_driver = None

    # Cleanup function
    def cleanup_driver():
        if web_driver:
            webpage.DestroyWebDriver(web_driver)

    # Fetch function
    def attempt_metadata_fetch():
        nonlocal web_driver

        # Create web driver
        web_driver = webpage.CreateWebDriver(make_headless = True)
        if not web_driver:
            raise Exception("Failed to create web driver")

        # Get search terms
        search_terms = gameinfo.DeriveGameSearchTermsFromName(game_name, game_platform)

        # Metadata result
        metadata_result = metadataentry.MetadataEntry()

        # Load url
        success = webpage.LoadUrl(web_driver, "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=" + search_terms)
        if not success:
            raise Exception("Failed to load BigFishGames search page")

        # Look for game description
        element_game_description = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "productFullDetail__descriptionContent"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not element_game_description:
            return None  # No description found, might be no results

        # Look for game bullets
        element_game_bullets = webpage.WaitForElement(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "productFullDetail__bullets"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

        # Grab the description text
        raw_game_description = webpage.GetElementText(element_game_description)

        # Grab the bullets text (if available)
        raw_game_bullets = ""
        if element_game_bullets:
            raw_game_bullets = webpage.GetElementText(element_game_bullets)

        # Convert to metadata format
        description_parts = []
        if isinstance(raw_game_description, str) and raw_game_description.strip():
            description_parts.append(raw_game_description.strip())
        if isinstance(raw_game_bullets, str) and raw_game_bullets.strip():
            description_parts.append(raw_game_bullets.strip())
        if description_parts:
            metadata_result.set_description("\n".join(description_parts))
        return metadata_result

    # Use retry function with cleanup
    result = datautils.retry_with_backoff(
        func = attempt_metadata_fetch,
        cleanup_func = cleanup_driver,
        max_retries = 3,
        initial_delay = 2,
        backoff_factor = 2,
        verbose = verbose,
        operation_name = "BigFishGames metadata fetch for '%s' (%s)" % (game_name, game_platform))

    # Final cleanup
    cleanup_driver()
    return result

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
