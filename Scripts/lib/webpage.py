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
import environment
import system
import ini

###########################################################

# Parse page source
def ParsePageSource(contents, features = "lxml"):
    try:
        import bs4
        return bs4.BeautifulSoup(contents, features=features)
    except:
        return None

# Parse html page source
def ParseHtmlPageSource(html_contents):
    return ParsePageSource(html_contents, features = "html.parser")

# Parse xml page source
def ParseXmlPageSource(xml_contents):
    return ParsePageSource(xml_contents, features = "xml")

###########################################################

# Create chrome web driver
def CreateChromeWebDriver(
    download_dir = None,
    profile_dir = None,
    binary_location = None,
    make_headless = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    webdriver_tool = None
    if programs.IsToolInstalled("ChromeDriver"):
        webdriver_tool = programs.GetToolProgram("ChromeDriver")
    if not webdriver_tool:
        system.LogError("ChromeDriver was not found")
        return None

    # Create web driver
    try:
        if verbose:
            system.LogInfo("Creating chrome web driver")
        if not pretend_run:
            from selenium.webdriver.chrome.service import Service as ChromeService
            from selenium.webdriver.chrome.options import Options as ChromeOptions
            from selenium.webdriver import Chrome
            service = ChromeService(webdriver_tool, log_path=os.path.devnull)
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
            if system.IsPathValid(binary_location) and system.DoesPathExist(binary_location):
                options.binary_location = binary_location
            web_driver = Chrome(service=service, options=options)
            return web_driver
        return None
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to create chrome web driver")
            system.LogError(e)
            system.QuitProgram()
    return None

# Create firefox web driver
def CreateFirefoxWebDriver(
    download_dir = None,
    profile_dir = None,
    binary_location = None,
    make_headless = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    webdriver_tool = None
    if programs.IsToolInstalled("GeckoDriver"):
        webdriver_tool = programs.GetToolProgram("GeckoDriver")
    if not webdriver_tool:
        system.LogError("GeckoDriver was not found")
        return None

    # Create web driver
    try:
        if verbose:
            system.LogInfo("Creating firefox web driver")
        if not pretend_run:
            from selenium.webdriver.firefox.service import Service as FirefoxService
            from selenium.webdriver.firefox.options import Options as FirefoxOptions
            from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
            from selenium.webdriver import Firefox
            service = FirefoxService(webdriver_tool, log_path=os.path.devnull)
            options = FirefoxOptions()
            if system.IsPathValid(download_dir) and system.DoesPathExist(download_dir):
                options.set_preference("browser.download.folderList", 2)
                options.set_preference("browser.download.dir", download_dir)
            if system.IsPathValid(profile_dir) and system.DoesPathExist(profile_dir):
                options.set_preference('profile', profile_dir)
            if make_headless:
                options.add_argument("--headless")
            if system.IsPathValid(binary_location) and system.DoesPathExist(binary_location):
                options.binary_location = binary_location
            web_driver = Firefox(service=service, options=options)
            return web_driver
        return None
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to create firefox web driver")
            system.LogError(e)
            system.QuitProgram()
    return None

# Create web driver
def CreateWebDriver(
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
        return CreateFirefoxWebDriver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.GetToolProgram("Firefox"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif driver_type == config.WebDriverType.CHROME:
        return CreateChromeWebDriver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.GetToolProgram("Chrome"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif driver_type == config.WebDriverType.BRAVE:
        return CreateChromeWebDriver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            binary_location = programs.GetToolProgram("Brave"),
            make_headless = make_headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return None

# Destroy web driver
def DestroyWebDriver(
    driver,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            system.LogInfo("Destroying web driver")
        if not pretend_run:
            if driver:
                driver.close()
                driver.quit()
        return True
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to destroy web driver")
            system.LogError(e)
            system.QuitProgram()
    return False

# Load url
def LoadUrl(
    driver,
    url,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            system.LogInfo("Loading url %s" % url)
        if not pretend_run:
            driver.get(url)
        return True
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to load url %s" % url)
            system.LogError(e)
            system.QuitProgram()
    return False

# Get current page url
def GetCurrentPageUrl(driver):
    if driver:
        return driver.current_url
    return None

# Check if page url is loaded
def IsUrlLoaded(driver, url):
    if driver:
        current_url = GetCurrentPageUrl(driver)
        if current_url:
            return current_url.startswith(url)
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
def WaitForAllElements(
    driver,
    locators = [],
    wait_time = 1000,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        conditions = [EC.presence_of_element_located(locator.Get()) for locator in locators]
        return WebDriverWait(driver, wait_time).until(
            EC.all_of(*conditions)
        )
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()
    return None

# Wait for any element
def WaitForAnyElement(
    driver,
    locators = [],
    wait_time = 1000,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        conditions = [EC.presence_of_element_located(locator.Get()) for locator in locators]
        return WebDriverWait(driver, wait_time).until(
            EC.any_of(*conditions)
        )
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()
    return None

# Wait for element
def WaitForElement(
    driver,
    locator,
    wait_time = 1000,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        return WebDriverWait(driver, wait_time).until(
            EC.presence_of_element_located(locator.Get())
        )
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()
    return None

# Get element
def GetElement(
    parent,
    locator,
    all_elements = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if all_elements:
            return parent.find_elements(*locator.Get())
        else:
            return parent.find_element(*locator.Get())
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()
    return None

# Get element text
def GetElementText(element):
    try:
        if element:
            return element.text
    except:
        pass
    return None

# Get element attribute
def GetElementAttribute(element, attribute_name):
    try:
        if element:
            return element.get_attribute(attribute_name)
    except:
        pass
    return None

# Get element children text
def GetElementChildrenText(element):
    attribute = GetElementAttribute(element, "innerHTML")
    if attribute:
        return system.ExtractWebText(attribute)
    return None

# Get element link url
def GetElementLinkUrl(element):
    element = GetElement(parent = element, locator = ElementLocator({"tag": "a"}))
    if element:
        return GetElementAttribute(element, "href")
    return None

# Click element
def ClickElement(
    element,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if element:
            element.click()
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()

# Send keys to element
def SendKeysToElement(
    element,
    keys,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if element:
            element.send_keys(keys)
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()

# Scroll to end of page
def ScrollToEndOfPage(
    driver,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight)")
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()

# Get page source
def GetPageSource(
    driver,
    url = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if url:
            driver.get(url)
        return str(driver.page_source)
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()
    return None

# Save cookie
def SaveCookie(
    driver,
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not system.IsPathValid(path):
        return False
    if not driver.get_cookies():
        return False
    success = system.MakeDirectory(
        dir = system.GetFilenameDirectory(path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    success = system.TouchFile(
        src = path,
        contents = json.dumps(driver.get_cookies()),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Load cookie
def LoadCookie(
    driver,
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not system.DoesPathExist(path):
        return False
    cookie_list = system.ReadJsonFile(
        src = path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if isinstance(cookie_list, list):
        for cookie in cookie_list:
            driver.add_cookie(cookie)
        return True
    return False

###########################################################

# Log into website
def LogIntoWebsite(
    driver,
    login_url,
    cookiefile,
    locator,
    wait_time = 1000,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Load the login page
    try:
        driver.get(login_url)
    except Exception as e:
        if exit_on_failure:
            system.LogError(e)
            system.QuitProgram()
        return False

    # Look for element
    login_check = WaitForElement(
        driver = driver,
        locator = locator,
        wait_time = wait_time,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not login_check:
        return False

    # Save cookie
    success = SaveCookie(
        driver = driver,
        path = cookiefile,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Get website text
def GetWebsiteText(
    url,
    params = {},
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # First, try webdriver
    driver = CreateWebDriver(
        make_headless = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if driver:
        page_text = GetPageSource(
            driver = driver,
            url = url,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        DestroyWebDriver(
            driver = driver,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return page_text

    # Next, try requests
    try:
        import requests
        reqs = requests.get(url, params=params)
        return reqs.text
    except Exception as e:
        pass

    # No results
    return ""

# Get all matching urls
def GetMatchingUrls(
    url,
    base_url,
    params = {},
    starts_with = "",
    ends_with = "",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get page text
    page_text = GetWebsiteText(
        url = url,
        params = params,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Parse the HTML page
    matching_urls = []
    parser = ParseHtmlPageSource(page_text)
    if parser:

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
                    value = system.JoinStringsAsUrl(base_url, value)
            return [value, system.StripStringQueryParams(value)]

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
                    potential_urls.append(system.StripStringQueryParams(value))

        # Look through text nodes to find links
        for value in parser.find_all(string=re.compile("^http")):
            potential_urls.append(value)
            potential_urls.append(system.StripStringQueryParams(value))

        # Filter URLs that match the starts_with and ends_with patterns
        for potential_url in potential_urls:
            if re.match("^%s.*%s$" % (starts_with, ends_with), potential_url):
                matching_urls.append(potential_url)
    return matching_urls

# Get matching url
def GetMatchingUrl(
    url,
    base_url,
    params = {},
    starts_with = "",
    ends_with = "",
    get_latest = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Find potential matching archive urls
    potential_urls = GetMatchingUrls(
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
        return None

    # Select final url
    matching_url = None
    if get_latest:
        potential_map = {}
        for potential_url in potential_urls:
            url_tokens = potential_url.split("/")
            if len(url_tokens) > 0:
                potential_map[url_tokens[-1]] = potential_url
        for potential_key in sorted(potential_map.keys(), reverse = True):
            matching_url = potential_map[potential_key]
            break
    else:
        matching_url = potential_urls[0]
    return matching_url

###########################################################
