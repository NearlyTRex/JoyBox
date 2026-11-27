# Steam lookups that need no account: store pages, covers and trailers, appid
# search, SteamGridDB covers, and reading the public store page.

# Local imports
from joybox import config
from joybox import containers
from joybox import datautils
from joybox import image
from joybox import logger
from joybox import modules
from joybox import network
from joybox import programs
from joybox import serialization
from joybox import settings
from joybox import strings
from joybox import webpage
from joybox import webfetch

# The store page URL for an appid; None when it is unreachable
def get_steam_page(appid):
    url = "https://store.steampowered.com/app/%s" % appid
    if network.is_url_reachable(url):
        return url
    return None

# The 600x900 library cover from the first Steam CDN that serves it; None when none does
def get_steam_cover(appid):
    for cdn_type in config.ContentDeliveryNetworkType.members():
        url = "https://cdn.%s.steamstatic.com/steam/apps/%s/library_600x900_2x.jpg" % (cdn_type.lower(), appid)
        if network.is_url_reachable(url):
            return url
    return None

# The first .mp4 store trailer linked from the app's store page, trying each Steam CDN; None when none is found
def get_steam_trailer(
    appid,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for cdn_type in config.ContentDeliveryNetworkType.members():
        asset_url = webfetch.get_matching_url(
            url = get_steam_page(appid),
            base_url = "https://video.%s.steamstatic.com/store_trailers" % cdn_type.lower(),
            starts_with = "https://video.%s.steamstatic.com/store_trailers" % cdn_type.lower(),
            ends_with = ".mp4",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if asset_url:
            return asset_url
    return None

# Entries of the SteamAppIDList CSV whose titles are highly similar to the name, each scored by similarity
def find_steam_appid_matches(
    search_name,
    verbose = False,
    exit_on_failure = False):

    # Load appid list
    appid_list = serialization.read_csv_file(
        src = programs.get_tool_path_config_value("SteamAppIDList", "csv"),
        headers = [config.SEARCH_RESULT_KEY_ID, config.SEARCH_RESULT_KEY_TITLE],
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Build list of matches
    search_results = []
    for entry in appid_list:
        search_result = containers.AssetSearchResult(entry)
        if strings.are_strings_highly_similar(search_name, search_result.get_title()):
            search_result.set_relevance(strings.get_string_similarity_ratio(search_name, search_result.get_title()))
            search_results.append(search_result)
    return search_results

# The best-scoring appid match, by default the best one whose store page is reachable; None when nothing matches
def find_steam_appid_match(
    search_name,
    only_active_pages = True,
    verbose = False,
    exit_on_failure = False):

    # Get relevant matches
    search_results = find_steam_appid_matches(
        search_name = search_name,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if len(search_results) == 0:
        return None

    # Return top search result
    ranked_results = sorted(search_results, key = lambda x: x.get_relevance(), reverse = True)
    if only_active_pages:
        for search_result in ranked_results:
            if get_steam_page(search_result.get_id()):
                return search_result
        return None
    return ranked_results[0]

# The cover or trailer of the best appid match, as a one-item result list; empty when none is found
def find_steam_assets(
    search_name,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get search result
    search_result = find_steam_appid_match(
        search_name = search_name,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not search_result:
        return []

    # Get asset url
    asset_url = None
    if asset_type == config.AssetType.BOXFRONT:
        asset_url = get_steam_cover(search_result.get_id())
    elif asset_type == config.AssetType.VIDEO:
        asset_url = get_steam_trailer(
            appid = search_result.get_id(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not asset_url:
        return []

    # Return search result
    search_result.set_url(asset_url)
    return [search_result]

# Find SteamGridDB covers
def find_steam_griddb_covers(
    search_name,
    image_dimensions = None,
    image_types = None,
    verbose = False,
    exit_on_failure = False):

    # Get authorization info
    steamgriddb_api_key = settings.get_value("UserData.Scraping", "steamgriddb_api_key")
    if not steamgriddb_api_key:
        logger.log_error("No steamgriddb_api_key in UserData.Scraping", quit_program = exit_on_failure)
        return []

    # Import steamgrid
    steamgrid = modules.import_python_module_package(
        module_path = programs.get_tool_path_config_value("PySteamGridDB", "package_dir"),
        module_name = programs.get_tool_config_value("PySteamGridDB", "package_name"))
    if not steamgrid:
        logger.log_error("PySteamGridDB is not installed", quit_program = exit_on_failure)
        return []

    # Initialize client
    if verbose:
        logger.log_info("Searching SteamGridDB for '%s'" % search_name)
    sgdb = steamgrid.SteamGridDB(steamgriddb_api_key)

    # Build search results
    search_results = []
    for game_entry in sgdb.search_game(strings.encode_url_string(search_name, use_plus = True)):
        search_grids = sgdb.get_grids_by_gameid(game_ids=[game_entry.id])
        if datautils.is_iterable_container(search_grids):
            for search_grid in search_grids:

                # Get grid info
                grid_id = game_entry.id
                grid_name = game_entry.name
                grid_release_date = game_entry.release_date
                grid_url = search_grid.url
                grid_width = int(search_grid.width)
                grid_height = int(search_grid.height)

                # Ignore dissimilar images
                if not strings.are_strings_highly_similar(search_name, grid_name):
                    continue

                # Ignore images that do not match requested dimensions
                if datautils.is_iterable_non_string(image_dimensions) and len(image_dimensions) == 2:
                    requested_width, requested_height = map(int, image_dimensions)
                    if grid_width != requested_width or grid_height != requested_height:
                        continue

                # Ignore images that do not match requested types
                if datautils.is_iterable_non_string(image_types) and len(image_types) > 0:
                    found_type = image.get_image_format(grid_url)
                    if found_type and found_type not in image_types:
                        continue

                # Add search result
                search_result = containers.AssetSearchResult()
                search_result.set_id(grid_id)
                search_result.set_title(grid_name)
                search_result.set_description(f"{grid_name} ({grid_release_date})")
                search_result.set_date(grid_release_date)
                search_result.set_url(grid_url)
                search_result.set_width(grid_width)
                search_result.set_height(grid_height)
                search_result.set_relevance(strings.get_string_similarity_ratio(search_name, grid_name))
                search_results.append(search_result)

    # Return search results
    return sorted(search_results, key=lambda x: x.get_relevance(), reverse = True)

# Answer the store page's age gate, when it shows one
def answer_steam_age_gate(web_driver, verbose = False):
    element_age_gate = webpage.wait_for_element(
        driver = web_driver,
        locator = webpage.ElementLocator({"id": "app_agegate"}),
        wait_time = 5,
        verbose = verbose,
        exit_on_failure = False)
    if not element_age_gate:
        return

    # Fill in a birth date and confirm it
    selectors = [
        webpage.get_element(
            parent = element_age_gate,
            locator = webpage.ElementLocator({"id": selector_id}),
            verbose = verbose,
            exit_on_failure = False)
        for selector_id in ("ageDay", "ageMonth", "ageYear")]
    if not all(selectors):
        return
    for selector, value in zip(selectors, ("1", "January", "1980"), strict = True):
        webpage.send_keys_to_element(selector, value)
    confirm_button = webpage.get_element(
        parent = element_age_gate,
        locator = webpage.ElementLocator({"id": "view_product_page_btn"}),
        verbose = verbose,
        exit_on_failure = False)
    if confirm_button:
        webpage.click_element(confirm_button)

# Read the release, developer, publisher and genre from the store page details
def read_steam_page_details(raw_game_details, metadata_entry):
    setters = {
        "Release Date:": lambda value: metadata_entry.set_release(strings.convert_date_string(value, "%b %d, %Y", "%Y-%m-%d")),
        "Developer:": metadata_entry.set_developer,
        "Publisher:": metadata_entry.set_publisher,
        "Genre:": lambda value: metadata_entry.set_genre(value.replace(", ", ";")),
    }
    for game_detail_line in raw_game_details.split("\n"):
        for label, setter in setters.items():
            if strings.does_string_start_with_substring(game_detail_line, label):
                setter(strings.trim_substring_from_start(game_detail_line, label).strip())
                break
