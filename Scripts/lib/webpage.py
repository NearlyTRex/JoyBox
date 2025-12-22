# Imports
import os, os.path
import sys
import pickle
import json
import re

# Local imports
import config
import command
import programs
import serialization
import strings
import environment
import fileops
import system
import text
import logger
import paths
import ini

###########################################################

# Parse page source
def parse_page_source(contents, features = "lxml"):
    try:
        import bs4
        return bs4.BeautifulSoup(contents, features=features)
    except:
        return None

# Parse html page source
def parse_html_page_source(html_contents):
    return parse_page_source(html_contents, features = "html.parser")

# Parse xml page source
def parse_xml_page_source(xml_contents):
    return parse_page_source(xml_contents, features = "xml")

###########################################################

# Create chrome web driver
def create_chrome_web_driver(
    download_dir = None,
    profile_dir = None,
    binary_location = None,
    make_headless = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    webdriver_tool = None
    if programs.is_tool_installed("ChromeDriver"):
        webdriver_tool = programs.get_tool_program("ChromeDriver")
    if not webdriver_tool:
        logger.log_error("ChromeDriver was not found")
        return None

    # Create web driver
    try:
        if verbose:
            logger.log_info("Creating chrome web driver")
        if not pretend_run:
            from selenium.webdriver.chrome.service import Service as ChromeService
            from selenium.webdriver.chrome.options import Options as ChromeOptions
            from selenium.webdriver import Chrome
            from webdriver_manager.chrome import ChromeDriverManager
            service = ChromeService(executable_path=ChromeDriverManager().install(), log_path=os.path.devnull)
            options = ChromeOptions()
            options.add_argument("--start-maximized")
            options.add_argument("--no-sandbox")
            options.add_argument("--ignore-certificate-errors")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            if make_headless:
                options.add_argument("--headless")
                options.add_argument("--window-size=1920,1080")
            if paths.is_path_valid(binary_location) and paths.does_path_exist(binary_location):
                options.binary_location = binary_location
            web_driver = Chrome(service=service, options=options)
            return web_driver
        return None
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to create chrome web driver")
            logger.log_error(e)
            system.quit_program()
    return None

# Create firefox web driver
def create_firefox_web_driver(
    download_dir = None,
    profile_dir = None,
    binary_location = None,
    make_headless = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    webdriver_tool = None
    if programs.is_tool_installed("GeckoDriver"):
        webdriver_tool = programs.get_tool_program("GeckoDriver")
    if not webdriver_tool:
        logger.log_error("GeckoDriver was not found")
        return None

    # Create web driver
    try:
        if verbose:
            logger.log_info("Creating firefox web driver")
        if not pretend_run:
            from selenium.webdriver.firefox.service import Service as FirefoxService
            from selenium.webdriver.firefox.options import Options as FirefoxOptions
            from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
            from selenium.webdriver import Firefox
            from webdriver_manager.firefox import GeckoDriverManager
            service = FirefoxService(executable_path=GeckoDriverManager().install())
            options = FirefoxOptions()
            if paths.is_path_valid(download_dir) and paths.does_path_exist(download_dir):
                options.set_preference("browser.download.folderList", 2)
                options.set_preference("browser.download.dir", download_dir)
            if paths.is_path_valid(profile_dir) and paths.does_path_exist(profile_dir):
                options.set_preference('profile', profile_dir)
            if make_headless:
                options.add_argument("--headless")
            if paths.is_path_valid(binary_location) and paths.does_path_exist(binary_location):
                options.binary_location = binary_location
            web_driver = Firefox(service=service, options=options)
            return web_driver
        return None
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to create firefox web driver")
            logger.log_error(e)
            system.quit_program()
    return None

# Create web driver
def create_web_driver(
    driver_type = None,
    download_dir = None,
    profile_dir = None,
    make_headless = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not driver_type:
        driver_type = config.WebDriverType.from_string(ini.GetIniValue("UserData.Scraping", "web_driver_type"))
    if not driver_type:
        driver_type = config.WebDriverType.FIREFOX
    if driver_type == config.WebDriverType.FIREFOX:
        return create_firefox_web_driver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.get_tool_program("Firefox"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif driver_type == config.WebDriverType.CHROME:
        return create_chrome_web_driver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.get_tool_program("Chrome"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif driver_type == config.WebDriverType.BRAVE:
        return create_chrome_web_driver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.get_tool_program("Brave"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return None

# Destroy web driver
def destroy_web_driver(
    driver,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Destroying web driver")
        if not pretend_run:
            if driver:
                driver.close()
                driver.quit()
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to destroy web driver")
            logger.log_error(e)
            system.quit_program()
    return False

# Load url
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
            driver.get(url)
        return True
    except Exception as e:
        if verbose:
            logger.log_warning("LoadUrl: Failed to load URL '%s': %s" % (url, str(e)))
        if exit_on_failure:
            logger.log_error("Unable to load url %s" % url)
            logger.log_error(e)
            system.quit_program()
    return False

# Get current page url
def get_current_page_url(driver, verbose = False):
    try:
        if not is_session_valid(driver, verbose):
            return None
        return driver.current_url
    except Exception as e:
        if verbose:
            logger.log_warning("GetCurrentPageUrl: Failed to get current URL: %s" % str(e))
        return None

# Check if page url is loaded
def is_url_loaded(driver, url, verbose = False):
    try:
        if not is_session_valid(driver, verbose):
            return False
        if not url or not isinstance(url, str):
            if verbose:
                logger.log_warning("IsUrlLoaded: Invalid URL provided")
            return False
        current_url = get_current_page_url(driver, verbose)
        if current_url:
            return current_url.startswith(url)
        return False
    except Exception as e:
        if verbose:
            logger.log_warning("IsUrlLoaded: Failed to check if URL is loaded: %s" % str(e))
        return False

###########################################################

# Element locator
class ElementLocator:
    def __init__(self, info):
        from selenium.webdriver.common.by import By
        self.by_type = None
        self.by_value = None
        if isinstance(info, dict) and len(info) == 1:
            for key, value in info.items():
                if key == "id":
                    self.by_type = By.ID
                elif key == "name":
                    self.by_type = By.NAME
                elif key == "class":
                    self.by_type = By.CLASS_NAME
                elif key == "tag":
                    self.by_type = By.TAG_NAME
                elif key == "xpath":
                    self.by_type = By.XPATH
                elif key == "css_selector":
                    self.by_type = By.CSS_SELECTOR
                elif key == "link_text":
                    self.by_type = By.LINK_TEXT
                elif key == "partial_link_text":
                    self.by_type = By.PARTIAL_LINK_TEXT
                else:
                    raise ValueError("Unsupported locator type: %s" % key)
                self.by_value = value
        else:
            raise ValueError("Locator dictionary should contain exactly one key-value pair.")
    def Get(self):
        return (self.by_type, self.by_value)

# Wait for all elements
def wait_for_all_elements(
    driver,
    locators = [],
    wait_time = 1000,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        if verbose:
            logger.log_info("WaitForAllElements: Waiting for all %d element(s) (timeout: %d seconds)" % (len(locators), wait_time))
            for i, locator in enumerate(locators):
                logger.log_info("  Locator %d: %s" % (i + 1, str(locator.Get())))
        conditions = [EC.presence_of_element_located(locator.Get()) for locator in locators]
        result = WebDriverWait(driver, wait_time).until(
            EC.all_of(*conditions)
        )
        if verbose:
            logger.log_info("WaitForAllElements: All elements found successfully")
        return result
    except Exception as e:
        if verbose:
            logger.log_warning("WaitForAllElements: Failed to find all elements: %s" % str(e))
        if exit_on_failure:
            logger.log_error(e)
            system.quit_program()
    return None

# Wait for any element
def wait_for_any_element(
    driver,
    locators = [],
    wait_time = 1000,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        if verbose:
            logger.log_info("WaitForAnyElement: Waiting for any of %d element(s) (timeout: %d seconds)" % (len(locators), wait_time))
            for i, locator in enumerate(locators):
                logger.log_info("  Locator %d: %s" % (i + 1, str(locator.Get())))
        conditions = [EC.presence_of_element_located(locator.Get()) for locator in locators]
        result = WebDriverWait(driver, wait_time).until(
            EC.any_of(*conditions)
        )
        if verbose:
            logger.log_info("WaitForAnyElement: Found at least one element")
        return result
    except Exception as e:
        if verbose:
            logger.log_warning("WaitForAnyElement: Failed to find any elements: %s" % str(e))
        if exit_on_failure:
            logger.log_error(e)
            system.quit_program()
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
        if hasattr(obj, 'current_url'):
            obj.current_url
        return True
    except Exception:
        if verbose:
            logger.log_warning("Object session invalid")
        return False

# Wait for element
def wait_for_element(
    driver,
    locator,
    wait_time = 15,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import TimeoutException, WebDriverException
        if verbose:
            logger.log_info("WaitForElement: Waiting for element (timeout: %d seconds)" % wait_time)
            logger.log_info("  Locator: %s" % str(locator.Get()))
        if not is_session_valid(driver, verbose):
            return None
        element = WebDriverWait(driver, wait_time).until(EC.presence_of_element_located(locator.Get()))
        if verbose:
            logger.log_info("WaitForElement: Element found successfully")
        return element
    except TimeoutException:
        if verbose:
            logger.log_warning("WaitForElement: Timeout waiting for element after %d seconds" % wait_time)
            logger.log_warning("  Locator: %s" % str(locator.Get()))
        return None
    except WebDriverException as e:
        if verbose:
            logger.log_warning("WaitForElement: WebDriver error: %s" % str(e))
        return None
    except Exception as e:
        if verbose:
            logger.log_warning("WaitForElement: Unexpected error: %s" % str(e))
        if exit_on_failure:
            logger.log_error(e)
            system.quit_program()
        return None

# Get element
def get_element(
    parent,
    locator,
    all_elements = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        from selenium.common.exceptions import NoSuchElementException, WebDriverException
        if verbose:
            logger.log_info("GetElement: Searching for element%s" % (" (all instances)" if all_elements else ""))
            logger.log_info("  Locator: %s" % str(locator.Get()))
        if not is_session_valid(parent, verbose):
            return None
        if all_elements:
            elements = parent.find_elements(*locator.Get())
            if verbose:
                logger.log_info("GetElement: Found %d element(s)" % len(elements))
            return elements
        else:
            element = parent.find_element(*locator.Get())
            if verbose:
                logger.log_info("GetElement: Element found successfully")
            return element
    except NoSuchElementException:
        if verbose:
            logger.log_warning("GetElement: Element not found")
            logger.log_warning("  Locator: %s" % str(locator.Get()))
        return None
    except WebDriverException as e:
        if verbose:
            logger.log_warning("GetElement: WebDriver error: %s" % str(e))
        return None
    except Exception as e:
        if verbose:
            logger.log_warning("GetElement: Unexpected error: %s" % str(e))
        if exit_on_failure:
            logger.log_error(e)
            system.quit_program()
        return None

# Get element text
def get_element_text(element, verbose = False):
    try:
        if not element:
            if verbose:
                logger.log_warning("GetElementText: Element is None")
            return None
        return element.text
    except Exception as e:
        if verbose:
            logger.log_warning("GetElementText: Failed to get element text: %s" % str(e))
        return None

# Get element attribute
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
    except Exception as e:
        if verbose:
            logger.log_warning("GetElementAttribute: Failed to get attribute '%s': %s" % (attribute_name, str(e)))
        return None

# Get element children text
def get_element_children_text(element, verbose = False):
    try:
        if not element:
            if verbose:
                logger.log_warning("GetElementChildrenText: Element is None")
            return None
        attribute = get_element_attribute(element, "innerHTML", verbose)
        if attribute:
            return text.extract_web_text(attribute)
        return None
    except Exception as e:
        if verbose:
            logger.log_warning("GetElementChildrenText: Failed to get element children text: %s" % str(e))
        return None

# Get element link url
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
    except Exception as e:
        if verbose:
            logger.log_warning("GetElementLinkUrl: Failed to get element link URL: %s" % str(e))
        return None

# Click element
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
    except Exception as e:
        if verbose:
            logger.log_warning("ClickElement: Failed to click element: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to click element")
            logger.log_error(e)
            system.quit_program()
        return False

# Send keys to element
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
    except Exception as e:
        if verbose:
            logger.log_warning("SendKeysToElement: Failed to send keys: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to send keys to element")
            logger.log_error(e)
            system.quit_program()
        return False

# Scroll to end of page
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
    except Exception as e:
        if verbose:
            logger.log_warning("ScrollToEndOfPage: Failed to scroll: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to scroll to end of page")
            logger.log_error(e)
            system.quit_program()
        return False

# Get page source
def get_page_source(
    driver,
    url = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not is_session_valid(driver, verbose):
            return None
        if url:
            if not isinstance(url, str):
                if verbose:
                    logger.log_warning("GetPageSource: Invalid URL provided")
                return None
            success = load_url(driver, url, verbose, pretend_run, exit_on_failure)
            if not success:
                return None
        if verbose:
            logger.log_info("Getting page source")
        if not pretend_run:
            return str(driver.page_source)
        return ""
    except Exception as e:
        if verbose:
            logger.log_warning("GetPageSource: Failed to get page source: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to get page source")
            logger.log_error(e)
            system.quit_program()
        return None

###########################################################

# Save cookie
def save_cookie(
    driver,
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not is_session_valid(driver, verbose):
            return False
        if not paths.is_path_valid(path):
            if verbose:
                logger.log_warning("SaveCookie: Invalid path provided")
            return False
        cookies = driver.get_cookies()
        if not cookies:
            if verbose:
                logger.log_warning("SaveCookie: No cookies to save")
            return False
        if verbose:
            logger.log_info("Saving cookies to %s" % path)
        success = fileops.make_directory(
            src = paths.get_filename_directory(path),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            if verbose:
                logger.log_warning("SaveCookie: Failed to create cookie directory")
            return False
        success = fileops.touch_file(
            src = path,
            contents = json.dumps(cookies),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if success and verbose:
            logger.log_info("Successfully saved cookies")
        return success
    except Exception as e:
        if verbose:
            logger.log_warning("SaveCookie: Failed to save cookies: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to save cookies")
            logger.log_error(e)
            system.quit_program()
        return False

# Load cookie
def load_cookie(
    driver,
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not is_session_valid(driver, verbose):
            return False
        if not paths.does_path_exist(path):
            if verbose:
                logger.log_warning("LoadCookie: Cookie file does not exist: %s" % path)
            return False
        if verbose:
            logger.log_info("Loading cookies from %s" % path)
        cookie_list = serialization.read_json_file(
            src = path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not isinstance(cookie_list, list):
            if verbose:
                logger.log_warning("LoadCookie: Cookie file does not contain valid cookie list")
            return False
        if not pretend_run:
            cookies_loaded = 0
            for cookie in cookie_list:
                try:
                    driver.add_cookie(cookie)
                    cookies_loaded += 1
                except Exception as cookie_error:
                    if verbose:
                        logger.log_warning("LoadCookie: Failed to add cookie: %s" % str(cookie_error))
            if verbose:
                logger.log_info("Successfully loaded %d cookies" % cookies_loaded)
        return True
    except Exception as e:
        if verbose:
            logger.log_warning("LoadCookie: Failed to load cookies: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to load cookies")
            logger.log_error(e)
            system.quit_program()
        return False

# Get cookie file
def get_cookie_file(base_name):
    cookie_file = base_name + config.cookie_suffix_path
    cookie_dir = environment.get_cookie_directory()
    return paths.join_paths(cookie_dir, cookie_file)

###########################################################

# Login cookie website
def login_cookie_website(
    driver,
    url,
    cookie,
    locator,
    wait_time = 1000,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Load the login page
    success = load_url(
        driver = driver,
        url = url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Look for element
    login_check = wait_for_element(
        driver = driver,
        locator = locator,
        wait_time = wait_time,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not login_check:
        return False

    # Save cookie
    success = save_cookie(
        driver = driver,
        path = cookie,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Load cookie website
def load_cookie_website(
    driver,
    url,
    cookie,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # First load of cookie url
    success = load_url(
        driver = driver,
        url = url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Load cookie file
    success = load_cookie(
        driver = driver,
        path = cookie,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Load cookie url a second time
    success = load_url(
        driver = driver,
        url = url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################

# Get website text
def get_website_text(
    url,
    params = {},
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
    driver = create_web_driver(
        make_headless = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if driver:
        if verbose:
            logger.log_info("GetWebsiteText: Web driver created successfully")
        page_text = get_page_source(
            driver = driver,
            url = url,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        destroy_web_driver(
            driver = driver,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if page_text:
            if verbose:
                logger.log_info("GetWebsiteText: Successfully fetched content using web driver (%d chars)" % len(page_text))
            return page_text
        else:
            if verbose:
                logger.log_warning("GetWebsiteText: Web driver returned empty content")

    # Next, try requests
    if verbose:
        logger.log_info("GetWebsiteText: Attempting to fetch using requests library")
    try:
        import requests
        reqs = requests.get(url, params=params)
        if verbose:
            logger.log_info("GetWebsiteText: Successfully fetched content using requests (%d chars)" % len(reqs.text))
        return reqs.text
    except Exception as e:
        if verbose:
            logger.log_warning("GetWebsiteText: Requests library failed: %s" % str(e))

    # No results
    if verbose:
        logger.log_warning("GetWebsiteText: All fetch methods failed, returning empty string")
    return ""

# Get all matching urls
def get_matching_urls(
    url,
    base_url,
    params = {},
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
    parser = parse_html_page_source(page_text)
    if parser:
        if verbose:
            logger.log_info("GetMatchingUrls: Parsing HTML content for URLs")

        # List to store potential URLs
        potential_urls = []

        # Process tag url
        def ProcessTagUrl(value, base_url, is_iframe = False):
            if not value:
                return []
            if not value.startswith("http"):
                if is_iframe and value.startswith("//"):
                    value = "https:" + value
                elif not is_iframe:
                    value = strings.join_strings_as_url(base_url, value)
            return [value, strings.strip_string_query_params(value)]

        # Look through tags to find links
        for tag in parser.find_all("a", href=True):
            value = tag.get("href")
            potential_urls.extend(ProcessTagUrl(value, base_url))
        for tag in parser.find_all("iframe", src=True):
            value = tag.get("src")
            potential_urls.extend(ProcessTagUrl(value, base_url, is_iframe=True))

        # Look through tag attributes to find links
        for tag in parser.find_all(True):
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and re.match(r'https?://', value):
                    potential_urls.append(value)
                    potential_urls.append(strings.strip_string_query_params(value))

        # Look through text nodes to find links
        for value in parser.find_all(string=re.compile("^http")):
            potential_urls.append(value)
            potential_urls.append(strings.strip_string_query_params(value))

        # Filter URLs that match the starts_with and ends_with patterns
        if verbose:
            logger.log_info("GetMatchingUrls: Found %d potential URLs, filtering by pattern" % len(potential_urls))
        for potential_url in potential_urls:
            if re.match("^%s.*%s$" % (starts_with, ends_with), potential_url):
                matching_urls.append(potential_url)
                if verbose:
                    logger.log_info("  Matched: %s" % potential_url)
    else:
        if verbose:
            logger.log_warning("GetMatchingUrls: Failed to parse HTML page")

    if verbose:
        logger.log_info("GetMatchingUrls: Returning %d matching URL(s)" % len(matching_urls))
    return matching_urls

# Get matching url
def get_matching_url(
    url,
    base_url,
    params = {},
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
    if len(potential_urls) == 0:
        if verbose:
            logger.log_warning("GetMatchingUrl: No matching URLs found")
        return None
    if verbose:
        logger.log_info("GetMatchingUrl: Found %d potential URL(s)" % len(potential_urls))

    # Select final url
    matching_url = None
    if get_latest:
        potential_map = {}
        for potential_url in potential_urls:
            url_tokens = potential_url.split("/")
            if len(url_tokens) > 0:
                potential_map[url_tokens[-1]] = potential_url
        if verbose:
            logger.log_info("GetMatchingUrl: Sorting %d URLs to find latest" % len(potential_map))
        for potential_key in sorted(potential_map.keys(), reverse = True):
            matching_url = potential_map[potential_key]
            if verbose:
                logger.log_info("GetMatchingUrl: Selected latest URL key: %s" % potential_key)
            break
    else:
        matching_url = potential_urls[0]
        if verbose:
            logger.log_info("GetMatchingUrl: Selected first URL from list")
    if verbose:
        logger.log_info("GetMatchingUrl: Final result: %s" % matching_url)
    return matching_url

###########################################################
