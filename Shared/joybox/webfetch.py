# Fetching a page's text, and finding the links on a page that match a pattern.

# Imports
import re

# Local imports
from joybox import logger
from joybox import runtime
from joybox import strings
from joybox import webpage

# Seconds a plain request may take before it is abandoned
REQUEST_TIMEOUT_SECONDS = 30

# Get website text
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
    if verbose:
        logger.log_info("GetWebsiteText: Attempting to fetch using web driver")
    driver = webpage.create_web_driver(
        make_headless = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if driver:
        if verbose:
            logger.log_info("GetWebsiteText: Web driver created successfully")
        try:
            page_text = webpage.get_page_source(
                driver = driver,
                url = url,
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

    # Next, try requests
    if verbose:
        logger.log_info("GetWebsiteText: Attempting to fetch using requests library")
    import requests
    try:
        reqs = requests.get(url, params = params, timeout = REQUEST_TIMEOUT_SECONDS)
        reqs.raise_for_status()
        if verbose:
            logger.log_info("GetWebsiteText: Successfully fetched content using requests (%d chars)" % len(reqs.text))
        return reqs.text
    except requests.RequestException as e:
        if verbose:
            logger.log_warning("GetWebsiteText: Requests library failed: %s" % str(e))

    # No results
    if exit_on_failure:
        logger.log_error("Unable to fetch website text from %s" % url)
        runtime.quit_program()
    if verbose:
        logger.log_warning("GetWebsiteText: All fetch methods failed, returning empty string")
    return ""

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
        logger.log_info("GetMatchingUrls: Starting URL discovery")
        logger.log_info("  URL: %s" % url)
        logger.log_info("  Base URL: %s" % base_url)
        logger.log_info("  Pattern: starts_with='%s', ends_with='%s'" % (starts_with, ends_with))

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
        if verbose:
            logger.log_info("GetMatchingUrls: Parsing HTML content for URLs")

        # List to store potential URLs
        potential_urls = []

        # Process tag url
        def process_tag_url(value, base_url, is_iframe = False):
            if not value:
                return []
            if not value.startswith("http"):
                if is_iframe and value.startswith("//"):
                    value = "https:" + value
                else:
                    value = strings.join_strings_as_url(base_url, value)
            return [value, strings.strip_string_query_params(value)]

        # Look through tags to find links
        for tag in parser.find_all("a", href=True):
            value = tag.get("href")
            potential_urls.extend(process_tag_url(value, base_url))
        for tag in parser.find_all("iframe", src=True):
            value = tag.get("src")
            potential_urls.extend(process_tag_url(value, base_url, is_iframe=True))

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

        # Filter URLs that match the starts_with and ends_with patterns
        if verbose:
            logger.log_info("GetMatchingUrls: Found %d potential URLs, filtering by pattern" % len(potential_urls))
        seen_urls = set()
        for potential_url in potential_urls:
            if potential_url in seen_urls:
                continue
            if re.match("^%s.*%s$" % (starts_with, ends_with), potential_url):
                seen_urls.add(potential_url)
                matching_urls.append(potential_url)
                if verbose:
                    logger.log_info("  Matched: %s" % potential_url)
    else:
        if verbose:
            logger.log_warning("GetMatchingUrls: Failed to parse HTML page")

    if verbose:
        logger.log_info("GetMatchingUrls: Returning %d matching URL(s)" % len(matching_urls))
    return matching_urls

# Get natural sort key, so that numbered names order by value rather than by digit
def get_natural_sort_key(value):
    return [int(token) if token.isdigit() else token.lower() for token in re.split(r"(\d+)", value)]

# Get matching url
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
        logger.log_info("GetMatchingUrl: Searching for matching URL")
        logger.log_info("  URL: %s" % url)
        logger.log_info("  Base URL: %s" % base_url)
        logger.log_info("  Starts with: '%s'" % starts_with)
        logger.log_info("  Ends with: '%s'" % ends_with)
        logger.log_info("  Get latest: %s" % get_latest)
        if params:
            logger.log_info("  Params: %s" % params)

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
    if get_latest:
        potential_map = {}
        for potential_url in potential_urls:
            potential_map[potential_url.split("/")[-1]] = potential_url
        if verbose:
            logger.log_info("GetMatchingUrl: Sorting %d URLs to find latest" % len(potential_map))
        latest_key = max(potential_map.keys(), key = get_natural_sort_key)
        matching_url = potential_map[latest_key]
        if verbose:
            logger.log_info("GetMatchingUrl: Selected latest URL key: %s" % latest_key)
    else:
        matching_url = potential_urls[0]
        if verbose:
            logger.log_info("GetMatchingUrl: Selected first URL from list")
    if verbose:
        logger.log_info("GetMatchingUrl: Final result: %s" % matching_url)
    return matching_url
