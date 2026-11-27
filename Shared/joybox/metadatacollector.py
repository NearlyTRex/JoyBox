# Imports
import collections
import functools

# Local imports
from joybox import config
from joybox import logger
from joybox import strings
from joybox import gamenaming
from joybox import webpage
from joybox import metadataentry

############################################################

# Fetch result for a page behind a bot challenge; not None, so retries stop at once
BLOCKED = object()

# Bot challenges in a row after which a source is not asked again this run
BLOCKED_STREAK_LIMIT = 3

# Bot challenges each source has served in a row, this run
blocked_streaks = collections.Counter()

# Note whether a source fetch was challenged, giving up on the source after a run of them
def note_blocked(source_name, blocked):
    if not blocked:
        blocked_streaks[source_name] = 0
        return
    blocked_streaks[source_name] += 1
    if blocked_streaks[source_name] == BLOCKED_STREAK_LIMIT:
        logger.log_warning("%s served a bot challenge %d games in a row; not asking it again this run" % (
            source_name, BLOCKED_STREAK_LIMIT))

# Whether a source has been given up on for this run
def is_given_up(source_name):
    return blocked_streaks[source_name] >= BLOCKED_STREAK_LIMIT

# Per-run tally of what each metadata source produced
class CollectionStats:
    source_outcomes = ("filled", "empty", "blocked", "given up", "unsupported", "skipped")
    game_outcomes = ("complete", "partial", "nothing found")

    def __init__(self):
        self.sources = {}
        self.games = collections.Counter()

    # Count one outcome for a source
    def record_source(self, source_name, outcome):
        self.sources.setdefault(source_name, collections.Counter())[outcome] += 1

    # Count how complete one game's collected metadata came back
    def record_game(self, outcome):
        self.games[outcome] += 1

    # One line per source, then one for the games
    def summary_lines(self):
        def describe(counts, outcomes):
            return ", ".join("%d %s" % (counts[outcome], outcome) for outcome in outcomes if counts[outcome])
        lines = ["%s: %s" % (source_name, describe(counts, self.source_outcomes)) for source_name, counts in self.sources.items()]
        if self.games:
            lines.append("Games: %s" % describe(self.games, self.game_outcomes))
        return lines

    # Sources that were challenged every time they were actually fetched
    def fully_blocked_sources(self):
        return [source_name for source_name, counts in self.sources.items()
            if counts["blocked"] and not counts["filled"] and not counts["empty"]]

    # Log the summary, warning about any source that was blocked throughout
    def log_summary(self):
        lines = self.summary_lines()
        if not lines:
            return
        logger.log_info("Metadata collection summary:")
        for line in lines:
            logger.log_info("  " + line)
        for source_name in self.fully_blocked_sources():
            logger.log_warning("%s served a bot challenge for every game it was asked about" % source_name)

# Record one source outcome, if a tally is being kept
def record_source_outcome(stats, source_name, outcome):
    if stats is not None:
        stats.record_source(source_name, outcome)

# Record what a source fetch produced and give its caller-facing result
def finish_source_fetch(stats, source_name, result):
    if result is BLOCKED:
        outcome = "blocked"
    elif isinstance(result, metadataentry.MetadataEntry) and result.game_entry:
        outcome = "filled"
    else:
        outcome = "empty"
    note_blocked(source_name, result is BLOCKED)
    record_source_outcome(stats, source_name, outcome)
    return None if result is BLOCKED else result

############################################################

# Fresh headless browser for one fetch attempt, without exiting on failure; falsy when none was made
def open_fetch_web_driver(verbose = False, pretend_run = False):
    return webpage.create_web_driver(
        make_headless = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = False)

# Close a fetch browser, if one was opened
def close_fetch_web_driver(web_driver, verbose = False, pretend_run = False):
    if web_driver:
        webpage.destroy_web_driver(
            driver = web_driver,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

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
        close_fetch_web_driver(web_driver, verbose = verbose, pretend_run = pretend_run)
        web_driver = None

    # Fetch function
    def attempt_fetch():
        nonlocal web_driver
        web_driver = open_fetch_web_driver(verbose = verbose, pretend_run = pretend_run)
        if not web_driver:
            if pretend_run:
                return None
            raise webpage.ScrapeFailed("Failed to create web driver")
        return fetch_func(web_driver)

    # Use retry function with cleanup
    try:
        return webpage.retry_scrape(
            func = attempt_fetch,
            cleanup_func = cleanup_driver,
            verbose = verbose,
            operation_name = operation_name)
    finally:

        # Final cleanup
        cleanup_driver()

# Convert a release value to a date, None if unparsable
def convert_release_date(release_text):
    return strings.convert_unknown_date_string(release_text, "%Y-%m-%d")

# Apply one stripped "Label: value" line through the first matching field's setters
def apply_detail_line(metadata_result, detail_line, detail_fields):
    for detail_label, detail_setters, detail_convert in detail_fields:
        if not strings.does_string_start_with_substring(detail_line, detail_label):
            continue
        detail_value = strings.trim_substring_from_start(detail_line, detail_label).strip()
        if detail_convert:
            detail_value = detail_convert(detail_value)
        if detail_value:
            for detail_setter in detail_setters:
                detail_setter(metadata_result, detail_value)
        return

# Read "Label: value" detail lines into a metadata entry, skipping empty values
def apply_detail_lines(metadata_result, detail_lines, detail_fields):
    for detail_line in detail_lines:
        if not isinstance(detail_line, str):
            continue
        apply_detail_line(metadata_result, detail_line.strip(), detail_fields)

############################################################

# TheGamesDB detail labels, the entry setters each fills and its value conversion
TGDB_DETAIL_FIELDS = [
    ("Genre(s):", [metadataentry.MetadataEntry.set_genre], lambda text: text.replace(" | ", ";")),
    ("Co-op:", [metadataentry.MetadataEntry.set_coop], None),
    ("Developer(s):", [metadataentry.MetadataEntry.set_developer], None),
    ("Publishers(s):", [metadataentry.MetadataEntry.set_publisher], None),
    ("Players:", [metadataentry.MetadataEntry.set_players], None),
    ("ReleaseDate:", [metadataentry.MetadataEntry.set_release], convert_release_date)]

# TheGamesDB result cards whose title is at least the minimum match score, each with its similarity ratio
def score_tgdb_search_results(element_search_result, natural_name, verbose = False):
    scores_list = []
    game_cells = webpage.get_element(
        parent = element_search_result,
        locator = webpage.ElementLocator({"class": "card-footer"}),
        all_elements = True,
        verbose = verbose,
        exit_on_failure = False)
    for game_cell in game_cells or []:

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
    min_match_score = webpage.get_min_match_score()
    return [score_entry for score_entry in scores_list if score_entry["ratio"] >= min_match_score]

# Fill description and detail fields from an open TheGamesDB game page
def read_tgdb_game_page(web_driver, metadata_result, verbose = False):

    # Look for game description
    element_game_description = webpage.wait_for_element(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "game-overview"}),
        verbose = verbose,
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
        exit_on_failure = False)
    for element_game_details in element_game_details_list or []:
        element_paragraphs = webpage.get_element(
            parent = element_game_details,
            locator = webpage.ElementLocator({"tag": "p"}),
            all_elements = True,
            verbose = verbose,
            exit_on_failure = False)
        if element_paragraphs:
            apply_detail_lines(
                metadata_result = metadata_result,
                detail_lines = [webpage.get_element_text(element_paragraph) for element_paragraph in element_paragraphs],
                detail_fields = TGDB_DETAIL_FIELDS)

# Search TheGamesDB with the platform filter and read the best-matching game; None when nothing matches
def fetch_tgdb_metadata(web_driver, game_name, platform_filter, verbose = False):

    # Get search terms
    search_terms = gamenaming.derive_game_search_terms_from_name(game_name)

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Load url
    success = webpage.load_url(web_driver, "https://thegamesdb.net/search.php?name=" + search_terms + platform_filter)
    if not success:
        raise webpage.ScrapeFailed("Failed to load TheGamesDB search page")

    # Get natural name
    natural_name = gamenaming.derive_regular_name_from_game_name(game_name)

    # Find the root container element
    element_search_result = webpage.wait_for_element(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "container-fluid"}),
        verbose = verbose,
        exit_on_failure = False)
    if not element_search_result:
        return None  # No search results found, not an error

    # Score each potential title compared to the original title
    scores_list = score_tgdb_search_results(element_search_result, natural_name, verbose = verbose)
    if not scores_list:
        return None  # No titled result close enough, not an error

    # Click on the highest score element
    best_entry = max(scores_list, key = lambda d: d["ratio"])
    webpage.click_element(best_entry["element"])

    # Check if the url has changed
    if webpage.is_url_loaded(web_driver, "https://thegamesdb.net/search.php?name="):
        return None  # Still on search page, no valid result found
    read_tgdb_game_page(web_driver, metadata_result, verbose = verbose)
    return metadata_result

# Collect metadata from TheGamesDB
def collect_metadata_from_tgdb(
    game_platform,
    game_name,
    stats = None,
    verbose = False,
    pretend_run = False):

    # Get TheGamesDB platform ids
    tgdb_platform_ids = config.tgdb_platforms.get(game_platform)
    if not tgdb_platform_ids:
        record_source_outcome(stats, "TheGamesDB", "unsupported")
        return None
    platform_filter = "".join("&platform_id%5B%5D=" + platform_id for platform_id in tgdb_platform_ids)

    # Fetch with retries
    result = fetch_with_web_driver(
        fetch_func = functools.partial(fetch_tgdb_metadata, game_name = game_name, platform_filter = platform_filter, verbose = verbose),
        operation_name = "TheGamesDB metadata fetch for '%s' (%s)" % (game_name, game_platform),
        verbose = verbose,
        pretend_run = pretend_run)
    return finish_source_fetch(stats, "TheGamesDB", result)

############################################################

# GameFAQs detail labels, the entry setters each fills and its value conversion
GAMEFAQS_DETAIL_FIELDS = [
    ("Genre:", [metadataentry.MetadataEntry.set_genre], lambda text: text.replace(" » ", ";")),
    ("Developer:", [metadataentry.MetadataEntry.set_developer], None),
    ("Publisher:", [metadataentry.MetadataEntry.set_publisher], None),
    ("Developer/Publisher:", [metadataentry.MetadataEntry.set_developer, metadataentry.MetadataEntry.set_publisher], None),
    ("Release:", [metadataentry.MetadataEntry.set_release], convert_release_date),
    ("First Released:", [metadataentry.MetadataEntry.set_release], convert_release_date)]

# Load a GameFAQs page, raising ScrapeFailed with the message when it fails; True when it is a bot challenge
def open_gamefaqs_page(web_driver, url, failure_message, verbose = False):
    if not webpage.load_url(web_driver, url):
        raise webpage.ScrapeFailed(failure_message)
    return webpage.is_challenge_page(web_driver, verbose = verbose)

# Load the GameFAQs homepage and check its marker, raising ScrapeFailed when either fails; True on a bot challenge
def open_gamefaqs_homepage(web_driver, verbose = False):
    if open_gamefaqs_page(web_driver, "https://gamefaqs.gamespot.com", "Failed to load GameFAQs homepage", verbose = verbose):
        return True
    element_homepage_marker = webpage.wait_for_element(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "home_jbi_ft"}),
        verbose = verbose,
        exit_on_failure = False)
    if not element_homepage_marker:
        raise webpage.ScrapeFailed("GameFAQs homepage marker not found")
    return False

# Rows of the GameFAQs search results table; None when there is no table
def get_gamefaqs_search_rows(element_search_result, verbose = False):
    elements_search_table = webpage.get_element(
        parent = element_search_result,
        locator = webpage.ElementLocator({"tag": "tbody"}),
        verbose = verbose,
        exit_on_failure = False)
    if not elements_search_table:
        return None
    return webpage.get_element(
        parent = elements_search_table,
        locator = webpage.ElementLocator({"tag": "tr"}),
        all_elements = True,
        verbose = verbose,
        exit_on_failure = False)

# Platform text and game link of a GameFAQs search row; None when the row lacks either or the game name
def read_gamefaqs_search_row(elements_search_row, verbose = False):
    elements_search_cols = webpage.get_element(
        parent = elements_search_row,
        locator = webpage.ElementLocator({"tag": "td"}),
        all_elements = True,
        verbose = verbose,
        exit_on_failure = False)
    if not elements_search_cols or len(elements_search_cols) < 4:
        return None
    search_platform = elements_search_cols[0]
    search_game = elements_search_cols[1]
    search_game_platform = webpage.get_element_children_text(search_platform)
    search_game_name = webpage.get_element_children_text(search_game)
    search_game_link = webpage.get_element_link_url(search_game)
    if not search_game_platform or not search_game_name or not search_game_link:
        return None
    return search_game_platform, search_game_link

# Load the first search row on the platform whose page opens; False when none does
def open_gamefaqs_platform_result(web_driver, elements_search_rows, gamefaqs_platform, verbose = False):
    for elements_search_row in elements_search_rows or []:
        search_row = read_gamefaqs_search_row(elements_search_row, verbose = verbose)
        if not search_row:
            continue
        search_game_platform, search_game_link = search_row
        if search_game_platform.strip() == gamefaqs_platform and webpage.load_url(web_driver, search_game_link):
            return True
    return False

# Fill the description from an open GameFAQs game page, expanding it through "more »" first
def read_gamefaqs_description(web_driver, metadata_result, verbose = False):
    element_game_description = webpage.wait_for_element(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "game_desc"}),
        verbose = verbose,
        exit_on_failure = False)
    if not element_game_description:
        return

    # Grab the description text
    raw_game_description = webpage.get_element_text(element_game_description)

    # Click the "more" button if it's present
    if raw_game_description and "more »" in raw_game_description:
        element_game_description_more = webpage.get_element(
            parent = web_driver,
            locator = webpage.ElementLocator({"link_text": "more »"}),
            verbose = verbose,
            exit_on_failure = False)
        if element_game_description_more:
            webpage.click_element(element_game_description_more)
            raw_game_description = webpage.get_element_text(element_game_description)

    # Convert description to metadata format
    if isinstance(raw_game_description, str) and raw_game_description.strip():
        metadata_result.set_description(raw_game_description)

# Fill the detail fields from an open GameFAQs game page
def read_gamefaqs_details(web_driver, metadata_result, verbose = False):
    element_game_details_list = webpage.get_element(
        parent = web_driver,
        locator = webpage.ElementLocator({"class": "content"}),
        all_elements = True,
        verbose = verbose,
        exit_on_failure = False)
    if element_game_details_list:
        apply_detail_lines(
            metadata_result = metadata_result,
            detail_lines = [webpage.get_element_text(element_game_details) for element_game_details in element_game_details_list],
            detail_fields = GAMEFAQS_DETAIL_FIELDS)

# Search GameFAQs through its homepage and read the first game on the platform; BLOCKED on a bot challenge
def fetch_gamefaqs_metadata(web_driver, game_name, gamefaqs_platform, verbose = False):

    # Get search terms
    search_terms = gamenaming.derive_game_search_terms_from_name(game_name)

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Load homepage
    if open_gamefaqs_homepage(web_driver, verbose = verbose):
        return BLOCKED

    # Load search URL
    if open_gamefaqs_page(web_driver, "https://gamefaqs.gamespot.com/search?game=" + search_terms, "Failed to load GameFAQs search page", verbose = verbose):
        return BLOCKED

    # Look for search results
    element_search_result = webpage.wait_for_element(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "span12"}),
        verbose = verbose,
        exit_on_failure = False)
    if not element_search_result:
        return None  # No search results found, not an error

    # Navigate to the first result on this platform
    elements_search_rows = get_gamefaqs_search_rows(element_search_result, verbose = verbose)
    if not open_gamefaqs_platform_result(web_driver, elements_search_rows, gamefaqs_platform, verbose = verbose):
        return None  # No result on this platform, not an error
    read_gamefaqs_description(web_driver, metadata_result, verbose = verbose)
    read_gamefaqs_details(web_driver, metadata_result, verbose = verbose)
    return metadata_result

# Scrape description, genre, developer, publisher and release from the first GameFAQs hit on the platform; None when blocked or unsupported
def collect_metadata_from_gamefaqs(
    game_platform,
    game_name,
    stats = None,
    verbose = False,
    pretend_run = False):

    # Get GameFAQs platform name
    gamefaqs_platform_info = config.gamefaqs_platforms.get(game_platform)
    if not gamefaqs_platform_info:
        record_source_outcome(stats, "GameFAQs", "unsupported")
        return None
    gamefaqs_platform = gamefaqs_platform_info[0]

    # Fetch with retries
    result = fetch_with_web_driver(
        fetch_func = functools.partial(fetch_gamefaqs_metadata, game_name = game_name, gamefaqs_platform = gamefaqs_platform, verbose = verbose),
        operation_name = "GameFAQs metadata fetch for '%s' (%s)" % (game_name, game_platform),
        verbose = verbose,
        pretend_run = pretend_run)
    return finish_source_fetch(stats, "GameFAQs", result)

############################################################

# Stripped description and bullets text joined by a newline, leaving out either when blank
def join_bigfishgames_description(raw_game_description, raw_game_bullets):
    description_parts = []
    if isinstance(raw_game_description, str) and raw_game_description.strip():
        description_parts.append(raw_game_description.strip())
    if isinstance(raw_game_bullets, str) and raw_game_bullets.strip():
        description_parts.append(raw_game_bullets.strip())
    return "\n".join(description_parts)

# Read the description and feature bullets from the BigFishGames search page; None when there is no description
def fetch_bigfishgames_metadata(web_driver, game_name, verbose = False):

    # Get search terms
    search_terms = gamenaming.derive_game_search_terms_from_name(game_name)

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Load url
    success = webpage.load_url(web_driver, "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query=" + search_terms)
    if not success:
        raise webpage.ScrapeFailed("Failed to load BigFishGames search page")

    # Look for game description
    element_game_description = webpage.wait_for_element(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "productFullDetail__descriptionContent"}),
        verbose = verbose,
        exit_on_failure = False)
    if not element_game_description:
        return None  # No description found, might be no results

    # Look for game bullets
    element_game_bullets = webpage.wait_for_element(
        driver = web_driver,
        locator = webpage.ElementLocator({"class": "productFullDetail__bullets"}),
        verbose = verbose,
        exit_on_failure = False)

    # Grab the description and bullets text
    raw_game_description = webpage.get_element_text(element_game_description)
    raw_game_bullets = ""
    if element_game_bullets:
        raw_game_bullets = webpage.get_element_text(element_game_bullets)

    # Convert to metadata format
    description = join_bigfishgames_description(raw_game_description, raw_game_bullets)
    if description:
        metadata_result.set_description(description)
    return metadata_result

# Scrape the description and feature bullets from the BigFishGames search page; None when there is no description
def collect_metadata_from_bigfishgames(
    game_platform,
    game_name,
    stats = None,
    verbose = False,
    pretend_run = False):

    # Fetch with retries
    result = fetch_with_web_driver(
        fetch_func = functools.partial(fetch_bigfishgames_metadata, game_name = game_name, verbose = verbose),
        operation_name = "BigFishGames metadata fetch for '%s' (%s)" % (game_name, game_platform),
        verbose = verbose,
        pretend_run = pretend_run)
    return finish_source_fetch(stats, "BigFishGames", result)

############################################################

# Why a source is not asked about a game, or None to ask it
def get_skip_reason(source_name, metadata_result, keys_to_check):
    if not metadata_result.is_missing_data(keys_to_check):
        return "skipped"
    if is_given_up(source_name):
        return "given up"
    return None

# Merge GameFAQs then TheGamesDB results, skipping a source once the keys are filled, and tally the game in stats
def collect_metadata_from_all(
    game_platform,
    game_name,
    keys_to_check,
    stats = None,
    verbose = False,
    pretend_run = False):

    # Metadata result
    metadata_result = metadataentry.MetadataEntry()

    # Try each source in priority order; earlier sources keep their values
    sources = [("GameFAQs", collect_metadata_from_gamefaqs), ("TheGamesDB", collect_metadata_from_tgdb)]
    for source_name, collect_func in sources:
        skip_reason = get_skip_reason(source_name, metadata_result, keys_to_check)
        if skip_reason:
            record_source_outcome(stats, source_name, skip_reason)
            continue
        source_result = collect_func(
            game_platform = game_platform,
            game_name = game_name,
            stats = stats,
            verbose = verbose,
            pretend_run = pretend_run)
        if isinstance(source_result, metadataentry.MetadataEntry):
            metadata_result.merge(source_result)

    # Tally the game
    if stats is not None:
        if not metadata_result.game_entry:
            stats.record_game("nothing found")
        elif metadata_result.is_missing_data(keys_to_check):
            stats.record_game("partial")
        else:
            stats.record_game("complete")

    # Return result
    return metadata_result

############################################################
