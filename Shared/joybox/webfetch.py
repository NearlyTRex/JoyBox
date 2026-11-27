# Fetching a page's text, and finding the links on a page that match a pattern.

# Imports
import importlib
import re
import urllib.parse

# Local imports
from joybox import logger
from joybox import runtime
from joybox import strings
from joybox import webpage

# Get requests, imported on first use
def _get_requests():
    return importlib.import_module("requests")

# Seconds a plain request may take before it is abandoned
REQUEST_TIMEOUT_SECONDS = 30

# The url with params appended to its query string, encoded as requests encodes them
def _get_url_with_params(url, params):
    if not params:
        return url
    query = params if isinstance(params, str) else urllib.parse.urlencode(params, doseq = True)
    parts = urllib.parse.urlsplit(url)
    joined = "&".join(part for part in (parts.query, query) if part)
    return urllib.parse.urlunsplit(parts._replace(query = joined))

# Page source fetched with a headless web driver, else with requests; empty when both fail
def get_website_text(
    url,
    params = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Log attempt
    if verbose:
        logger.log_info("GetWebsiteText: Fetching content from URL: %s" % url)
        if params:
            logger.log_info("  Params: %s" % params)

    # First, try webdriver
    page_text = _fetch_with_web_driver(url, params, verbose, pretend_run, exit_on_failure)
    if page_text:
        return page_text

    # Next, try requests
    page_text = _fetch_with_requests(url, params, verbose)
    if page_text is not None:
        return page_text

    # No results
    if exit_on_failure:
        logger.log_error("Unable to fetch website text from %s" % url)
        runtime.quit_program()
    if verbose:
        logger.log_warning("GetWebsiteText: All fetch methods failed, returning empty string")
    return ""

# Page source loaded in a headless web driver, closed afterwards; None when no driver starts or the page is empty
def _fetch_with_web_driver(url, params, verbose, pretend_run, exit_on_failure):
    if verbose:
        logger.log_info("GetWebsiteText: Attempting to fetch using web driver")
    driver = webpage.create_web_driver(
        make_headless = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not driver:
        return None
    if verbose:
        logger.log_info("GetWebsiteText: Web driver created successfully")
    try:
        page_text = webpage.get_page_source(
            driver = driver,
            url = _get_url_with_params(url, params),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    finally:
        webpage.destroy_web_driver(
            driver = driver,
            verbose = verbose,
            pretend_run = pretend_run)
    if page_text:
        if verbose:
            logger.log_info("GetWebsiteText: Successfully fetched content using web driver (%d chars)" % len(page_text))
        return page_text
    if verbose:
        logger.log_warning("GetWebsiteText: Web driver returned empty content")
    return None

# Response text of a plain GET request, even when empty; None when the request fails
def _fetch_with_requests(url, params, verbose):
    if verbose:
        logger.log_info("GetWebsiteText: Attempting to fetch using requests library")
    requests = _get_requests()
    try:
        reqs = requests.get(url, params = params, timeout = REQUEST_TIMEOUT_SECONDS)
        reqs.raise_for_status()
        if verbose:
            logger.log_info("GetWebsiteText: Successfully fetched content using requests (%d chars)" % len(reqs.text))
        return reqs.text
    except requests.RequestException as e:
        if verbose:
            logger.log_warning("GetWebsiteText: Requests library failed: %s" % str(e))
    return None

# Get all matching urls
def get_matching_urls(
    url,
    base_url,
    params = None,
    starts_with = "",
    ends_with = "",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Log attempt
    if verbose:
        _log_url_discovery(url, base_url, starts_with, ends_with)

    # Get page text
    page_text = get_website_text(
        url = url,
        params = params,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not page_text:
        if verbose:
            logger.log_warning("GetMatchingUrls: Failed to fetch page content")
        return []
    if verbose:
        logger.log_info("GetMatchingUrls: Successfully fetched page content (%d chars)" % len(page_text))

    # Parse the HTML page
    matching_urls = []
    parser = webpage.parse_html_page_source(page_text)
    if parser:
        matching_urls = _find_matching_page_urls(parser, base_url, starts_with, ends_with, verbose)
    elif verbose:
        logger.log_warning("GetMatchingUrls: Failed to parse HTML page")

    if verbose:
        logger.log_info("GetMatchingUrls: Returning %d matching URL(s)" % len(matching_urls))
    return matching_urls

# Log the page, base and pattern a url discovery runs with
def _log_url_discovery(url, base_url, starts_with, ends_with):
    logger.log_info("GetMatchingUrls: Starting URL discovery")
    logger.log_info("  URL: %s" % url)
    logger.log_info("  Base URL: %s" % base_url)
    logger.log_info("  Pattern: starts_with='%s', ends_with='%s'" % (starts_with, ends_with))

# A link or iframe value made absolute against base_url, with and without its query; empty for no value
# Protocol-relative iframe sources get https
def _process_tag_url(value, base_url, is_iframe = False):
    if not value:
        return []
    if not value.startswith("http"):
        if is_iframe and value.startswith("//"):
            value = "https:" + value
        else:
            value = strings.join_strings_as_url(base_url, value)
    return [value, strings.strip_string_query_params(value)]

# The distinct urls in a parsed page matching starts_with and ends_with, in the order found
def _find_matching_page_urls(parser, base_url, starts_with, ends_with, verbose):
    if verbose:
        logger.log_info("GetMatchingUrls: Parsing HTML content for URLs")
    potential_urls = find_potential_page_urls(parser, base_url)

    # Filter URLs that match the starts_with and ends_with patterns
    if verbose:
        logger.log_info("GetMatchingUrls: Found %d potential URLs, filtering by pattern" % len(potential_urls))
    matching_urls = []
    seen_urls = set()
    for potential_url in potential_urls:
        if potential_url in seen_urls:
            continue
        if re.match("^%s.*%s$" % (starts_with, ends_with), potential_url):
            seen_urls.add(potential_url)
            matching_urls.append(potential_url)
            if verbose:
                logger.log_info("  Matched: %s" % potential_url)
    return matching_urls

# Every url in a parsed page's links, iframes, attributes and text, each also without its query
def find_potential_page_urls(parser, base_url):

    # List to store potential URLs
    potential_urls = []

    # Look through tags to find links
    for tag in parser.find_all("a", href=True):
        value = tag.get("href")
        potential_urls.extend(_process_tag_url(value, base_url))
    for tag in parser.find_all("iframe", src=True):
        value = tag.get("src")
        potential_urls.extend(_process_tag_url(value, base_url, is_iframe=True))

    # Look through tag attributes to find links
    for tag in parser.find_all(True):
        for value in tag.attrs.values():
            if isinstance(value, str) and re.match(r'https?://', value):
                potential_urls.append(value)
                potential_urls.append(strings.strip_string_query_params(value))

    # Look through text nodes to find links
    for value in parser.find_all(string=re.compile(r"^\s*https?://")):
        value = str(value).strip()
        potential_urls.append(value)
        potential_urls.append(strings.strip_string_query_params(value))
    return potential_urls

# Get natural sort key, so that numbered names order by value rather than by digit
def get_natural_sort_key(value):
    return [int(token) if token.isdigit() else token.lower() for token in re.split(r"(\d+)", value)]

# First url on the page matching starts_with and ends_with, or with get_latest the one whose
# last path segment sorts highest naturally; None when nothing matches
def get_matching_url(
    url,
    base_url,
    params = None,
    starts_with = "",
    ends_with = "",
    get_latest = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Log attempt
    if verbose:
        _log_url_search(url, base_url, params, starts_with, ends_with, get_latest)

    # Find potential matching archive urls
    potential_urls = get_matching_urls(
        url = url,
        base_url = base_url,
        params = params,
        starts_with = starts_with,
        ends_with = ends_with,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Did not find any matching release
    if not potential_urls:
        if verbose:
            logger.log_warning("GetMatchingUrl: No matching URLs found")
        return None
    if verbose:
        logger.log_info("GetMatchingUrl: Found %d potential URL(s)" % len(potential_urls))

    # Select final url
    return _select_matching_url(potential_urls, get_latest, verbose)

# The latest of the urls when get_latest, else the first
def _select_matching_url(potential_urls, get_latest, verbose):
    if get_latest:
        matching_url = select_latest_url(potential_urls, verbose)
    else:
        matching_url = potential_urls[0]
        if verbose:
            logger.log_info("GetMatchingUrl: Selected first URL from list")
    if verbose:
        logger.log_info("GetMatchingUrl: Final result: %s" % matching_url)
    return matching_url

# Log the page, base, pattern and selection a single url search runs with
def _log_url_search(url, base_url, params, starts_with, ends_with, get_latest):
    logger.log_info("GetMatchingUrl: Searching for matching URL")
    logger.log_info("  URL: %s" % url)
    logger.log_info("  Base URL: %s" % base_url)
    logger.log_info("  Starts with: '%s'" % starts_with)
    logger.log_info("  Ends with: '%s'" % ends_with)
    logger.log_info("  Get latest: %s" % get_latest)
    if params:
        logger.log_info("  Params: %s" % params)

# The url whose last path segment sorts highest naturally; of urls sharing a segment, the last one listed
def select_latest_url(potential_urls, verbose = False):
    potential_map = {}
    for potential_url in potential_urls:
        potential_map[potential_url.split("/")[-1]] = potential_url
    if verbose:
        logger.log_info("GetMatchingUrl: Sorting %d URLs to find latest" % len(potential_map))
    latest_key = max(potential_map.keys(), key = get_natural_sort_key)
    if verbose:
        logger.log_info("GetMatchingUrl: Selected latest URL key: %s" % latest_key)
    return potential_map[latest_key]
