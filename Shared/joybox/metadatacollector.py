# Local imports
import joybox.config as config
import joybox.datautils as datautils
import joybox.strings as strings
import joybox.gameinfo as gameinfo
import joybox.webpage as webpage
import joybox.metadataentry as metadataentry

############################################################

# Run a page fetch in a fresh headless browser, retrying with backoff
def fetch_with_web_driver(
    fetch_func,
    operation_name,
    verbose = False,
    pretend_run = False):

    # Store web driver for cleanup
    web_driver = None

    # Cleanup function
    def cleanup_driver():
        nonlocal web_driver
        if web_driver:
            webpage.destroy_web_driver(
                driver = web_driver,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            web_driver = None

    # Fetch function
    def attempt_fetch():
        nonlocal web_driver
        web_driver = webpage.create_web_driver(
            make_headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not web_driver:
            if pretend_run:
                return None
            raise Exception("Failed to create web driver")
        return fetch_func(web_driver)

    # Use retry function with cleanup
    try:
        return datautils.retry_with_backoff(
            func = attempt_fetch,
            cleanup_func = cleanup_driver,
            max_retries = 3,
            initial_delay = 2,
            backoff_factor = 2,
            verbose = verbose,
            operation_name = operation_name)
    finally:

        # Final cleanup
        cleanup_driver()

# Convert a release value to a date, None if unparsable
def convert_release_date(release_text):
    return strings.convert_unknown_date_string(release_text, "%Y-%m-%d")

# Read "Label: value" detail lines into a metadata entry, skipping empty values
def apply_detail_lines(metadata_result, detail_lines, detail_fields):
    for detail_line in detail_lines:
        if not isinstance(detail_line, str):
            continue
        detail_line = detail_line.strip()
        for detail_label, detail_setters, detail_convert in detail_fields:
            if not strings.does_string_start_with_substring(detail_line, detail_label):
                continue
            detail_value = strings.trim_substring_from_start(detail_line, detail_label).strip()
            if detail_convert:
                detail_value = detail_convert(detail_value)
            if detail_value:
                for detail_setter in detail_setters:
                    detail_setter(metadata_result, detail_value)
            break

############################################################

# Collect metadata from TheGamesDB
def collect_metadata_from_tgdb(
    game_platform,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Fetch function
    def attempt_metadata_fetch(web_driver):

        # Get search terms
        search_terms = gameinfo.derive_game_search_terms_from_name(game_name, game_platform)

        # Metadata result
        metadata_result = metadataentry.MetadataEntry()

        # Load url
        success = webpage.load_url(web_driver, "https://thegamesdb.net/search.php?name=" + search_terms)
        if not success:
            raise Exception("Failed to load TheGamesDB search page")

        # Get natural name
        natural_name = gameinfo.derive_regular_name_from_game_name(game_name)

        # Find the root container element
        element_search_result = webpage.wait_for_element(
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
        game_cells = webpage.get_element(
            parent = element_search_result,
            locator = webpage.ElementLocator({"class": "card-footer"}),
            all_elements = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if game_cells:
            for game_cell in game_cells:

                # Get possible title
                game_cell_text = webpage.get_element_text(game_cell)
                potential_title = ""
                if game_cell_text:
                    potential_title = game_cell_text.split("\n")[0].strip()

                # Add comparison score
                if potential_title:
                    score_entry = {}
                    score_entry["element"] = game_cell
                    score_entry["ratio"] = strings.get_string_similarity_ratio(natural_name, potential_title)
                    scores_list.append(score_entry)

        if not scores_list:
            return None  # No titled results, not an error

        # Click on the highest score element
        best_entry = max(scores_list, key = lambda d: d["ratio"])
        webpage.click_element(best_entry["element"])

        # Check if the url has changed
        if webpage.is_url_loaded(web_driver, "https://thegamesdb.net/search.php?name="):
            return None  # Still on search page, no valid result found

        # Look for game description
        element_game_description = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "game-overview"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if element_game_description:
            raw_game_description = webpage.get_element_text(element_game_description)
            if raw_game_description and raw_game_description.strip():
                metadata_result.set_description(raw_game_description)

        # Look for game details
        element_game_details_list = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "card-body"}),
            all_elements = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if element_game_details_list:
            for element_game_details in element_game_details_list:
                element_paragraphs = webpage.get_element(
                    parent = element_game_details,
                    locator = webpage.ElementLocator({"tag": "p"}),
                    all_elements = True,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if element_paragraphs:
                    apply_detail_lines(
                        metadata_result = metadata_result,
                        detail_lines = [webpage.get_element_text(element_paragraph) for element_paragraph in element_paragraphs],
                        detail_fields = [
                            ("Genre(s):", [metadataentry.MetadataEntry.set_genre], lambda text: text.replace(" | ", ";")),
                            ("Co-op:", [metadataentry.MetadataEntry.set_coop], None),
                            ("Developer(s):", [metadataentry.MetadataEntry.set_developer], None),
                            ("Publishers(s):", [metadataentry.MetadataEntry.set_publisher], None),
                            ("Players:", [metadataentry.MetadataEntry.set_players], None),
                            ("ReleaseDate:", [metadataentry.MetadataEntry.set_release], convert_release_date)])
        return metadata_result

    # Fetch with retries
    return fetch_with_web_driver(
        fetch_func = attempt_metadata_fetch,
        operation_name = "TheGamesDB metadata fetch for '%s' (%s)" % (game_name, game_platform),
        verbose = verbose,
        pretend_run = pretend_run)

############################################################

# Collect metadata from GameFAQs
def collect_metadata_from_gamefaqs(
    game_platform,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get GameFAQs platform name
    gamefaqs_platform_info = config.gamefaqs_platforms.get(game_platform)
    if not gamefaqs_platform_info:
        return None
    gamefaqs_platform = gamefaqs_platform_info[0]

    # Fetch function
    def attempt_metadata_fetch(web_driver):

        # Get search terms
        search_terms = gameinfo.derive_game_search_terms_from_name(game_name, game_platform)

        # Metadata result
        metadata_result = metadataentry.MetadataEntry()

        # Load homepage
        success = webpage.load_url(web_driver, "https://gamefaqs.gamespot.com")
        if not success:
            raise Exception("Failed to load GameFAQs homepage")

        # Look for homepage marker
        element_homepage_marker = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "home_jbi_ft"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not element_homepage_marker:
            raise Exception("GameFAQs homepage marker not found")

        # Load search URL
        success = webpage.load_url(web_driver, "https://gamefaqs.gamespot.com/search_advanced?game=" + search_terms)
        if not success:
            raise Exception("Failed to load GameFAQs search page")

        # Look for search results
        element_search_result = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "span12"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not element_search_result:
            return None  # No search results found, not an error

        # Look for search table
        elements_search_rows = None
        elements_search_table = webpage.get_element(
            parent = element_search_result,
            locator = webpage.ElementLocator({"tag": "tbody"}),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if elements_search_table:
            elements_search_rows = webpage.get_element(
                parent = elements_search_table,
                locator = webpage.ElementLocator({"tag": "tr"}),
                all_elements = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)

        # Navigate to the first result on this platform
        game_page_loaded = False
        for elements_search_row in elements_search_rows or []:
            elements_search_cols = webpage.get_element(
                parent = elements_search_row,
                locator = webpage.ElementLocator({"tag": "td"}),
                all_elements = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
            if not elements_search_cols or len(elements_search_cols) < 4:
                continue
            search_platform = elements_search_cols[0]
            search_game = elements_search_cols[1]
            search_game_platform = webpage.get_element_children_text(search_platform)
            search_game_name = webpage.get_element_children_text(search_game)
            search_game_link = webpage.get_element_link_url(search_game)
            if not search_game_platform or not search_game_name or not search_game_link:
                continue
            if search_game_platform.strip() == gamefaqs_platform and webpage.load_url(web_driver, search_game_link):
                game_page_loaded = True
                break
        if not game_page_loaded:
            return None  # No result on this platform, not an error

        # Look for game description
        element_game_description = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "game_desc"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if element_game_description:

            # Grab the description text
            raw_game_description = webpage.get_element_text(element_game_description)

            # Click the "more" button if it's present
            if raw_game_description and "more »" in raw_game_description:
                element_game_description_more = webpage.get_element(
                    parent = web_driver,
                    locator = webpage.ElementLocator({"link_text": "more »"}),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if element_game_description_more:
                    webpage.click_element(element_game_description_more)
                    raw_game_description = webpage.get_element_text(element_game_description)

            # Convert description to metadata format
            if isinstance(raw_game_description, str) and raw_game_description.strip():
                metadata_result.set_description(raw_game_description)

        # Look for game details
        element_game_details_list = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"class": "content"}),
            all_elements = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if element_game_details_list:
            apply_detail_lines(
                metadata_result = metadata_result,
                detail_lines = [webpage.get_element_text(element_game_details) for element_game_details in element_game_details_list],
                detail_fields = [
                    ("Genre:", [metadataentry.MetadataEntry.set_genre], lambda text: text.replace(" » ", ";")),
                    ("Developer:", [metadataentry.MetadataEntry.set_developer], None),
                    ("Publisher:", [metadataentry.MetadataEntry.set_publisher], None),
                    ("Developer/Publisher:", [metadataentry.MetadataEntry.set_developer, metadataentry.MetadataEntry.set_publisher], None),
                    ("Release:", [metadataentry.MetadataEntry.set_release], convert_release_date),
                    ("First Released:", [metadataentry.MetadataEntry.set_release], convert_release_date)])
        return metadata_result

    # Fetch with retries
    return fetch_with_web_driver(
        fetch_func = attempt_metadata_fetch,
        operation_name = "GameFAQs metadata fetch for '%s' (%s)" % (game_name, game_platform),
        verbose = verbose,
        pretend_run = pretend_run)

############################################################

# Collect metadata from BigFishGames
def collect_metadata_from_bigfishgames(
    game_platform,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Fetch function
    def attempt_metadata_fetch(web_driver):

        # Get search terms
        search_terms = gameinfo.derive_game_search_terms_from_name(game_name, game_platform)

        # Metadata result
        metadata_result = metadataentry.MetadataEntry()

        # Load url
        success = webpage.load_url(web_driver, "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=" + search_terms)
        if not success:
            raise Exception("Failed to load BigFishGames search page")

        # Look for game description
        element_game_description = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "productFullDetail__descriptionContent"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not element_game_description:
            return None  # No description found, might be no results

        # Look for game bullets
        element_game_bullets = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator({"class": "productFullDetail__bullets"}),
            wait_time = 15,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

        # Grab the description text
        raw_game_description = webpage.get_element_text(element_game_description)

        # Grab the bullets text (if available)
        raw_game_bullets = ""
        if element_game_bullets:
            raw_game_bullets = webpage.get_element_text(element_game_bullets)

        # Convert to metadata format
        description_parts = []
        if isinstance(raw_game_description, str) and raw_game_description.strip():
            description_parts.append(raw_game_description.strip())
        if isinstance(raw_game_bullets, str) and raw_game_bullets.strip():
            description_parts.append(raw_game_bullets.strip())
        if description_parts:
            metadata_result.set_description("\n".join(description_parts))
        return metadata_result

    # Fetch with retries
    return fetch_with_web_driver(
        fetch_func = attempt_metadata_fetch,
        operation_name = "BigFishGames metadata fetch for '%s' (%s)" % (game_name, game_platform),
        verbose = verbose,
        pretend_run = pretend_run)

############################################################

# Collect metadata from all
def collect_metadata_from_all(
    game_platform,
    game_name,
    keys_to_check,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Try from GameFAQs
    metadata_result_gamefaqs = collect_metadata_from_gamefaqs(
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
