# Imports
import atexit
import os
import signal
import subprocess
import time
import importlib
import urllib.parse

# Local imports
from joybox import config
from joybox import datautils
from joybox import programs
from joybox import text
from joybox import logger
from joybox import paths
from joybox import settings
from joybox import runtime

# Get bs4, imported on first use
def _get_bs4():
    return importlib.import_module("bs4")

# Scraping limits; each can be overridden in UserData.Scraping
DEFAULT_ELEMENT_WAIT_SECONDS = 15
DEFAULT_FETCH_RETRIES = 3
DEFAULT_FETCH_RETRY_DELAY_SECONDS = 2
DEFAULT_MIN_MATCH_SCORE = 50
DEFAULT_PAGE_LOAD_INTERVAL_SECONDS = 3

# Seconds a stopped browser gets to exit before it is killed
BROWSER_STOP_SECONDS = 3

###########################################################

# A scraping limit from UserData.Scraping, never below its minimum
def get_scraping_limit(field, fallback, minimum = 0):
    value = settings.get_integer_value("UserData.Scraping", field, fallback, throw_exception = False)
    return max(fallback if value is None else value, minimum)

# Seconds to wait for an element before treating it as absent
def get_element_wait_seconds():
    return get_scraping_limit("element_wait_seconds", DEFAULT_ELEMENT_WAIT_SECONDS, minimum = 1)

# Attempts a page scrape gets before it is given up
def get_fetch_retries():
    return get_scraping_limit("fetch_retries", DEFAULT_FETCH_RETRIES, minimum = 1)

# Seconds before the first retry of a scrape; each later retry waits twice as long
def get_fetch_retry_delay_seconds():
    return get_scraping_limit("fetch_retry_delay_seconds", DEFAULT_FETCH_RETRY_DELAY_SECONDS)

# Lowest title similarity (0-100) a search result needs to be opened
def get_min_match_score():
    return get_scraping_limit("min_match_score", DEFAULT_MIN_MATCH_SCORE)

# Seconds between two page loads from the same site
def get_page_load_interval_seconds():
    return get_scraping_limit("page_load_interval_seconds", DEFAULT_PAGE_LOAD_INTERVAL_SECONDS)

# Get a selenium module, imported on first use so this module imports without it
def _get_selenium(module_name):
    return importlib.import_module("selenium." + module_name)

# Get a webdriver_manager module, imported on first use
def _get_webdriver_manager(module_name):
    return importlib.import_module("webdriver_manager." + module_name)

# Selenium's exceptions
def get_selenium_errors():
    return _get_selenium("common.exceptions")

# A scrape step that failed in a way another attempt may get past
class ScrapeFailed(Exception):
    pass

# Retry a scrape with the configured attempts and backoff, cleaning up between tries
def retry_scrape(func, cleanup_func = None, verbose = False, operation_name = None):
    return datautils.retry_with_backoff(
        func = func,
        retry_on = (ScrapeFailed, get_selenium_errors().WebDriverException),
        cleanup_func = cleanup_func,
        max_retries = get_fetch_retries(),
        initial_delay = get_fetch_retry_delay_seconds(),
        backoff_factor = 2,
        verbose = verbose,
        operation_name = operation_name)

###########################################################

# BeautifulSoup tree of the contents with the given parser, lxml by default; None when that parser is missing
def parse_page_source(contents, features = "lxml"):
    bs4 = _get_bs4()
    try:
        return bs4.BeautifulSoup(contents, features=features)
    except bs4.FeatureNotFound:
        return None

# BeautifulSoup tree using Python's built-in html.parser
def parse_html_page_source(html_contents):
    return parse_page_source(html_contents, features = "html.parser")

# BeautifulSoup tree using the lxml XML parser
def parse_xml_page_source(xml_contents):
    return parse_page_source(xml_contents, features = "xml")

###########################################################

# When each site last had a page loaded, by host
last_page_loads = {}

# Process groups of the browsers started and not yet stopped
running_browser_groups = set()

# Sleep between page loads
def pause(seconds):
    time.sleep(seconds)

# Wait out the rest of a site's page load interval, then note the load
def wait_for_page_load_turn(url):
    host = urllib.parse.urlsplit(url).hostname or ""
    last_load = last_page_loads.get(host)
    if last_load is not None:
        remaining = last_load + get_page_load_interval_seconds() - time.monotonic()
        if remaining > 0:
            pause(remaining)
    last_page_loads[host] = time.monotonic()

# Driver service options that start the driver, and the browser it launches, in
# a process group of their own; a launcher script such as brave-browser runs the
# browser as its child, so quitting the driver alone leaves the browser running
def get_driver_service_options():
    return {"popen_kw": {"start_new_session": True}} if hasattr(os, "killpg") else {}

# The process group a driver service runs in, or None
def get_service_group(service):
    pid = getattr(getattr(service, "process", None), "pid", None)
    return pid if isinstance(pid, int) and hasattr(os, "killpg") else None

# Send a signal to a process group, False once nothing in it is left
def signal_process_group(group_id, signal_number):
    try:
        os.killpg(group_id, signal_number)
        return True
    except OSError:
        return False

# Stop whatever is left in a browser's process group, killing what outlives the grace period
def stop_browser_group(group_id):
    if group_id is None:
        return
    running_browser_groups.discard(group_id)
    if not signal_process_group(group_id, signal.SIGTERM):
        return
    deadline = time.monotonic() + BROWSER_STOP_SECONDS
    while time.monotonic() < deadline:
        if not signal_process_group(group_id, 0):
            return
        pause(0.1)
    signal_process_group(group_id, signal.SIGKILL)

# Stop the browsers still running at exit, such as one an interrupt cut off
def stop_running_browsers():
    for group_id in list(running_browser_groups):
        stop_browser_group(group_id)

atexit.register(stop_running_browsers)

# Start a browser through its driver service, tracking its process group and
# stopping the group if the start fails
def start_browser(browser_class, service, options):
    try:
        web_driver = browser_class(service = service, options = options)
    except BaseException:
        stop_browser_group(get_service_group(service))
        raise
    group_id = get_service_group(service)
    if group_id is not None:
        running_browser_groups.add(group_id)
    return web_driver

# Whether the named web driver tool is installed, warning when it is not
def _find_webdriver_tool(tool_name):
    webdriver_tool = None
    if programs.is_tool_installed(tool_name):
        webdriver_tool = programs.get_tool_program(tool_name)
    if not webdriver_tool:
        logger.log_warning("%s was not found; callers may fall back to another fetch method" % tool_name)
        return False
    return True

# Chrome options for a maximized, sandboxless desktop browser, adding each given existing download dir,
# profile and binary, and headless at 1920x1080 when asked
def _get_chrome_options(download_dir, profile_dir, binary_location, make_headless):
    options = _get_selenium("webdriver.chrome.options").Options()
    options.add_argument("--start-maximized")
    options.add_argument("--no-sandbox")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    if paths.is_path_valid(download_dir) and paths.does_path_exist(download_dir):
        options.add_experimental_option("prefs", {
            "download.default_directory": download_dir,
            "download.prompt_for_download": False
        })
    if paths.is_path_valid(profile_dir) and paths.does_path_exist(profile_dir):
        options.add_argument("--user-data-dir=%s" % profile_dir)
    if make_headless:
        options.add_argument("--headless")
        options.add_argument("--window-size=1920,1080")
    if paths.is_path_valid(binary_location) and paths.does_path_exist(binary_location):
        options.binary_location = binary_location
    return options

# Firefox options adding each given existing download dir, profile and binary, and headless when asked
def _get_firefox_options(download_dir, profile_dir, binary_location, make_headless):
    options = _get_selenium("webdriver.firefox.options").Options()
    if paths.is_path_valid(download_dir) and paths.does_path_exist(download_dir):
        options.set_preference("browser.download.folderList", 2)
        options.set_preference("browser.download.dir", download_dir)
    if paths.is_path_valid(profile_dir) and paths.does_path_exist(profile_dir):
        options.profile = profile_dir
    if make_headless:
        options.add_argument("--headless")
    if paths.is_path_valid(binary_location) and paths.does_path_exist(binary_location):
        options.binary_location = binary_location
    return options

# Start a Chromium-based browser through webdriver_manager, with optional download dir, profile, binary and headless
# None when ChromeDriver is not installed or the browser fails to start
def create_chrome_web_driver(
    download_dir = None,
    profile_dir = None,
    binary_location = None,
    make_headless = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    if not _find_webdriver_tool("ChromeDriver"):
        return None

    # Create web driver
    try:
        if verbose:
            logger.log_info("Creating chrome web driver")
        if not pretend_run:
            driver_manager = _get_webdriver_manager("chrome").ChromeDriverManager()
            service = _get_selenium("webdriver.chrome.service").Service(
                executable_path = driver_manager.install(),
                log_output = subprocess.DEVNULL,
                **get_driver_service_options())
            options = _get_chrome_options(download_dir, profile_dir, binary_location, make_headless)
            return start_browser(_get_selenium("webdriver").Chrome, service, options)
        return None
    except (get_selenium_errors().WebDriverException, OSError, ValueError) as e:
        if verbose:
            logger.log_warning("CreateChromeWebDriver: Failed to create web driver: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to create chrome web driver")
            logger.log_error(e)
            runtime.quit_program()
    return None

# Start Firefox through webdriver_manager, with optional download dir, profile, binary and headless
# None when GeckoDriver is not installed or the browser fails to start
def create_firefox_web_driver(
    download_dir = None,
    profile_dir = None,
    binary_location = None,
    make_headless = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    if not _find_webdriver_tool("GeckoDriver"):
        return None

    # Create web driver
    try:
        if verbose:
            logger.log_info("Creating firefox web driver")
        if not pretend_run:
            driver_manager = _get_webdriver_manager("firefox").GeckoDriverManager()
            service = _get_selenium("webdriver.firefox.service").Service(
                executable_path = driver_manager.install(),
                log_output = subprocess.DEVNULL,
                **get_driver_service_options())
            options = _get_firefox_options(download_dir, profile_dir, binary_location, make_headless)
            return start_browser(_get_selenium("webdriver").Firefox, service, options)
        return None
    except (get_selenium_errors().WebDriverException, OSError, ValueError) as e:
        if verbose:
            logger.log_warning("CreateFirefoxWebDriver: Failed to create web driver: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to create firefox web driver")
            logger.log_error(e)
            runtime.quit_program()
    return None

# The given driver type, else the one the settings name, else Firefox
def _resolve_driver_type(driver_type):
    if not driver_type:
        driver_type_name = settings.get_value("UserData.Scraping", "web_driver_type", throw_exception = False)
        if isinstance(driver_type_name, str):
            driver_type = config.WebDriverType.from_string(driver_type_name)
    if not driver_type:
        driver_type = config.WebDriverType.FIREFOX
    return driver_type

# Start the browser the settings choose (Firefox, Chrome or Brave), Firefox when unset
def create_web_driver(
    driver_type = None,
    download_dir = None,
    profile_dir = None,
    make_headless = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    driver_type = _resolve_driver_type(driver_type)
    if driver_type == config.WebDriverType.FIREFOX:
        return create_firefox_web_driver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.get_tool_program("Firefox"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if driver_type == config.WebDriverType.CHROME:
        return create_chrome_web_driver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.get_tool_program("Chrome"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if driver_type == config.WebDriverType.BRAVE:
        return create_chrome_web_driver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.get_tool_program("Brave"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return None

# Quit the browser and stop its driver's process group; False when quitting fails
def destroy_web_driver(
    driver,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Destroying web driver")
        if not pretend_run and driver:
            group_id = get_service_group(getattr(driver, "service", None))
            try:
                # quit closes every window and stops the driver service, even
                # when the browser session is already gone
                driver.quit()
            finally:
                stop_browser_group(group_id)
        return True
    except (get_selenium_errors().WebDriverException, OSError) as e:
        if verbose:
            logger.log_warning("DestroyWebDriver: Failed to destroy web driver: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to destroy web driver")
            logger.log_error(e)
            runtime.quit_program()
    return False

# Navigate the browser to url after waiting out the site's page load interval; False on an invalid url or dead session
def load_url(
    driver,
    url,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not is_session_valid(driver, verbose):
            return False
        if not url or not isinstance(url, str):
            if verbose:
                logger.log_warning("LoadUrl: Invalid URL provided")
            return False
        logger.log_info("Loading url %s" % url)
        if not pretend_run:
            wait_for_page_load_turn(url)
            driver.get(url)
        return True
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("LoadUrl: Failed to load URL '%s': %s" % (url, str(e)))
        if exit_on_failure:
            logger.log_error("Unable to load url %s" % url)
            logger.log_error(e)
            runtime.quit_program()
    return False

# Url the browser is showing; None when the session is gone
def get_current_page_url(driver, verbose = False):
    try:
        if not is_session_valid(driver, verbose):
            return None
        return driver.current_url
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("GetCurrentPageUrl: Failed to get current URL: %s" % str(e))
        return None

# Check if page url is loaded
def is_url_loaded(driver, url, verbose = False):
    if not is_session_valid(driver, verbose):
        return False
    if not url or not isinstance(url, str):
        if verbose:
            logger.log_warning("IsUrlLoaded: Invalid URL provided")
        return False
    current_url = get_current_page_url(driver, verbose)
    if isinstance(current_url, str):
        return current_url.startswith(url)
    return False

# Check if the page is a Cloudflare bot challenge instead of the requested content
def is_challenge_page(driver, verbose = False):
    try:
        by = _get_selenium("webdriver.common.by").By
        if not is_session_valid(driver, verbose):
            return False
        if driver.find_elements(by.ID, "challenge-error-text"):
            if verbose:
                logger.log_warning("IsChallengePage: Bot challenge served for %s" % get_current_page_url(driver, verbose))
            return True
        return False
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("IsChallengePage: Failed to check for a bot challenge: %s" % str(e))
        return False

###########################################################

# Selenium By attribute for each locator key
LOCATOR_BY_ATTRIBUTES = {
    "id": "ID",
    "name": "NAME",
    "class": "CLASS_NAME",
    "tag": "TAG_NAME",
    "xpath": "XPATH",
    "css_selector": "CSS_SELECTOR",
    "link_text": "LINK_TEXT",
    "partial_link_text": "PARTIAL_LINK_TEXT",
}

# Element locator
class ElementLocator:
    def __init__(self, info):
        by = _get_selenium("webdriver.common.by").By
        self.by_type = None
        self.by_value = None
        if not isinstance(info, dict) or len(info) != 1:
            raise ValueError("Locator dictionary should contain exactly one key-value pair.")
        for key, value in info.items():
            if key not in LOCATOR_BY_ATTRIBUTES:
                raise ValueError("Unsupported locator type: %s" % key)
            self.by_type = getattr(by, LOCATOR_BY_ATTRIBUTES[key])
            self.by_value = value
    # The (By type, value) pair Selenium's find calls take
    def get(self):
        return (self.by_type, self.by_value)

# Wait until every locator matches; the found elements, or None on timeout; the configured
# element wait by default
def wait_for_all_elements(
    driver,
    locators = None,
    wait_time = None,
    verbose = False,
    exit_on_failure = False):
    if wait_time is None:
        wait_time = get_element_wait_seconds()
    try:
        support_ui = _get_selenium("webdriver.support.ui")
        expected_conditions = _get_selenium("webdriver.support.expected_conditions")
        if not locators:
            if verbose:
                logger.log_warning("WaitForAllElements: No locators provided")
            return None
        if not is_session_valid(driver, verbose):
            return None
        if verbose:
            logger.log_info("WaitForAllElements: Waiting for all %d element(s) (timeout: %d seconds)" % (len(locators), wait_time))
            for i, locator in enumerate(locators):
                logger.log_info("  Locator %d: %s" % (i + 1, str(locator.get())))
        conditions = [expected_conditions.presence_of_element_located(locator.get()) for locator in locators]
        result = support_ui.WebDriverWait(driver, wait_time).until(
            expected_conditions.all_of(*conditions)
        )
        if verbose:
            logger.log_info("WaitForAllElements: All elements found successfully")
        return result
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("WaitForAllElements: Failed to find all elements: %s" % str(e))
        if exit_on_failure:
            logger.log_error(e)
            runtime.quit_program()
    return None

# Wait until any locator matches; the first found, or None on timeout; the configured
# element wait by default
def wait_for_any_element(
    driver,
    locators = None,
    wait_time = None,
    verbose = False,
    exit_on_failure = False):
    if wait_time is None:
        wait_time = get_element_wait_seconds()
    try:
        support_ui = _get_selenium("webdriver.support.ui")
        expected_conditions = _get_selenium("webdriver.support.expected_conditions")
        if not locators:
            if verbose:
                logger.log_warning("WaitForAnyElement: No locators provided")
            return None
        if not is_session_valid(driver, verbose):
            return None
        if verbose:
            logger.log_info("WaitForAnyElement: Waiting for any of %d element(s) (timeout: %d seconds)" % (len(locators), wait_time))
            for i, locator in enumerate(locators):
                logger.log_info("  Locator %d: %s" % (i + 1, str(locator.get())))
        conditions = [expected_conditions.presence_of_element_located(locator.get()) for locator in locators]
        result = support_ui.WebDriverWait(driver, wait_time).until(
            expected_conditions.any_of(*conditions)
        )
        if verbose:
            logger.log_info("WaitForAnyElement: Found at least one element")
        return result
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("WaitForAnyElement: Failed to find any elements: %s" % str(e))
        if exit_on_failure:
            logger.log_error(e)
            runtime.quit_program()
    return None

# Check if session is valid for driver or element
def is_session_valid(
    obj,
    verbose = False):
    try:
        if not obj:
            if verbose:
                logger.log_warning("Object session is None")
            return False
        # Reading the URL raises once the browser session has gone away
        getattr(obj, "current_url", None)
        return True
    except get_selenium_errors().WebDriverException:
        if verbose:
            logger.log_warning("Object session invalid")
        return False

# Wait until the locator matches, the configured element wait by default; the element, or None on timeout
def wait_for_element(
    driver,
    locator,
    wait_time = None,
    verbose = False,
    exit_on_failure = False):
    if wait_time is None:
        wait_time = get_element_wait_seconds()
    try:
        support_ui = _get_selenium("webdriver.support.ui")
        expected_conditions = _get_selenium("webdriver.support.expected_conditions")
        if verbose:
            logger.log_info("WaitForElement: Waiting for element (timeout: %d seconds)" % wait_time)
            logger.log_info("  Locator: %s" % str(locator.get()))
        if not is_session_valid(driver, verbose):
            return None
        element = support_ui.WebDriverWait(driver, wait_time).until(expected_conditions.presence_of_element_located(locator.get()))
        if verbose:
            logger.log_info("WaitForElement: Element found successfully")
        return element
    except get_selenium_errors().TimeoutException:
        if verbose:
            logger.log_warning("WaitForElement: Timeout waiting for element after %d seconds" % wait_time)
            logger.log_warning("  Locator: %s" % str(locator.get()))
        return None
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("WaitForElement: WebDriver error: %s" % str(e))
        if exit_on_failure:
            logger.log_error(e)
            runtime.quit_program()
        return None

# First match under parent, or every match with all_elements; None when nothing matches
def get_element(
    parent,
    locator,
    all_elements = False,
    verbose = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("GetElement: Searching for element%s" % (" (all instances)" if all_elements else ""))
            logger.log_info("  Locator: %s" % str(locator.get()))
        if not is_session_valid(parent, verbose):
            return None
        if all_elements:
            elements = parent.find_elements(*locator.get())
            if verbose:
                logger.log_info("GetElement: Found %d element(s)" % len(elements))
            return elements
        element = parent.find_element(*locator.get())
        if verbose:
            logger.log_info("GetElement: Element found successfully")
        return element
    except get_selenium_errors().NoSuchElementException:
        if verbose:
            logger.log_warning("GetElement: Element not found")
            logger.log_warning("  Locator: %s" % str(locator.get()))
        return None
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("GetElement: WebDriver error: %s" % str(e))
        if exit_on_failure:
            logger.log_error(e)
            runtime.quit_program()
        return None

# Visible text of an element; None for a missing or stale element
def get_element_text(element, verbose = False):
    try:
        if not element:
            if verbose:
                logger.log_warning("GetElementText: Element is None")
            return None
        return element.text
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("GetElementText: Failed to get element text: %s" % str(e))
        return None

# Value of an element's attribute; None when the element or attribute name is missing
def get_element_attribute(element, attribute_name, verbose = False):
    try:
        if not element:
            if verbose:
                logger.log_warning("GetElementAttribute: Element is None")
            return None
        if not attribute_name or not isinstance(attribute_name, str):
            if verbose:
                logger.log_warning("GetElementAttribute: Invalid attribute name")
            return None
        return element.get_attribute(attribute_name)
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("GetElementAttribute: Failed to get attribute '%s': %s" % (attribute_name, str(e)))
        return None

# Readable text extracted from an element's inner HTML; None when it has none
def get_element_children_text(element, verbose = False):
    if not element:
        if verbose:
            logger.log_warning("GetElementChildrenText: Element is None")
        return None
    attribute = get_element_attribute(element, "innerHTML", verbose)
    if attribute:
        return text.extract_web_text(attribute)
    return None

# href of the first link inside an element; None when it contains no link
def get_element_link_url(element, verbose = False):
    try:
        if not element:
            if verbose:
                logger.log_warning("GetElementLinkUrl: Element is None")
            return None
        link_element = get_element(parent = element, locator = ElementLocator({"tag": "a"}), verbose = verbose)
        if link_element:
            return get_element_attribute(link_element, "href", verbose)
        return None
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("GetElementLinkUrl: Failed to get element link URL: %s" % str(e))
        return None

# Click an element unless pretending; False when it is missing or the click fails
def click_element(
    element,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not element:
            if verbose:
                logger.log_warning("ClickElement: Element is None")
            return False
        if verbose:
            logger.log_info("ClickElement: Attempting to click element")
        if not pretend_run:
            element.click()
        if verbose:
            logger.log_info("ClickElement: Successfully clicked element")
        return True
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("ClickElement: Failed to click element: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to click element")
            logger.log_error(e)
            runtime.quit_program()
        return False

# Type keys into an element unless pretending; False when it or the keys are missing
def send_keys_to_element(
    element,
    keys,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not element:
            if verbose:
                logger.log_warning("SendKeysToElement: Element is None")
            return False
        if keys is None:
            if verbose:
                logger.log_warning("SendKeysToElement: Keys is None")
            return False
        if verbose:
            logger.log_info("SendKeysToElement: Attempting to send keys to element (%d characters)" % len(str(keys)))
        if not pretend_run:
            element.send_keys(keys)
        if verbose:
            logger.log_info("SendKeysToElement: Successfully sent keys to element")
        return True
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("SendKeysToElement: Failed to send keys: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to send keys to element")
            logger.log_error(e)
            runtime.quit_program()
        return False

# Scroll the window to the bottom of the document; False when the session is gone
def scroll_to_end_of_page(
    driver,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not is_session_valid(driver, verbose):
            return False
        if verbose:
            logger.log_info("Scrolling to end of page")
        if not pretend_run:
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight)")
        return True
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("ScrollToEndOfPage: Failed to scroll: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to scroll to end of page")
            logger.log_error(e)
            runtime.quit_program()
        return False

# Load url in the driver for get_page_source; False when it is not a string or does not load
def _load_page_url(driver, url, verbose, pretend_run, exit_on_failure):
    if not isinstance(url, str):
        if verbose:
            logger.log_warning("GetPageSource: Invalid URL provided")
        return False
    return load_url(driver, url, verbose, pretend_run, exit_on_failure)

# Current page HTML, loading url first when given; empty on a pretend run, None on failure
def get_page_source(
    driver,
    url = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not is_session_valid(driver, verbose):
            return None
        if url and not _load_page_url(driver, url, verbose, pretend_run, exit_on_failure):
            return None
        if verbose:
            logger.log_info("Getting page source")
        if not pretend_run:
            return str(driver.page_source)
        return ""
    except get_selenium_errors().WebDriverException as e:
        if verbose:
            logger.log_warning("GetPageSource: Failed to get page source: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to get page source")
            logger.log_error(e)
            runtime.quit_program()
        return None
