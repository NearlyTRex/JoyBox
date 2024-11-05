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
    make_headless = False,
    verbose = False):
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver import Chrome
    webdriver_tool = None
    if programs.IsToolInstalled("ChromeDriver"):
        webdriver_tool = programs.GetToolProgram("ChromeDriver")
    if not webdriver_tool:
        system.LogError("ChromeDriver was not found")
        return None
    try:
        service = ChromeService(webdriver_tool, log_path=os.path.devnull)
        options = ChromeOptions()
        if make_headless:
            options.add_argument("--headless")
        web_driver = Chrome(service=service, options=options)
        return web_driver
    except Exception as e:
        if verbose:
            system.LogError(e)
    return None

# Create firefox web driver
def CreateFirefoxWebDriver(
    download_dir = None,
    profile_dir = None,
    make_headless = False,
    verbose = False):
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
    from selenium.webdriver import Firefox
    webdriver_tool = None
    if programs.IsToolInstalled("GeckoDriver"):
        webdriver_tool = programs.GetToolProgram("GeckoDriver")
    if not webdriver_tool:
        system.LogError("GeckoDriver was not found")
        return None
    try:
        service = FirefoxService(webdriver_tool, log_path=os.path.devnull)
        options = FirefoxOptions()
        if system.IsPathValid(download_dir) and system.DoesPathExist(download_dir):
            options.set_preference("browser.download.folderList", 2)
            options.set_preference("browser.download.dir", download_dir)
        if system.IsPathValid(profile_dir) and system.DoesPathExist(profile_dir):
            options.profile = FirefoxProfile(profile_directory = profile_dir)
        if make_headless:
            options.add_argument("--headless")
        options.binary_location = programs.GetToolProgram("Firefox")
        web_driver = Firefox(service=service, options=options)
        return web_driver
    except Exception as e:
        if verbose:
            system.LogError(e)
    return None

# Create web driver
def CreateWebDriver(
    driver_type = None,
    download_dir = None,
    profile_dir = None,
    make_headless = False,
    verbose = False):
    if not driver_type:
        driver_type = config.web_driver_type_firefox
    if driver_type == config.web_driver_type_chrome:
        return CreateChromeWebDriver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            make_headless = make_headless,
            verbose = verbose)
    elif driver_type == config.web_driver_type_firefox:
        return CreateFirefoxWebDriver(
            download_dir = download_dir,
            profile_dir = profile_dir,
            make_headless = make_headless,
            verbose = verbose)
    return None

# Destroy web driver
def DestroyWebDriver(driver, verbose = False):
    try:
        if driver:
            driver.quit()
        return True
    except Exception as e:
        if verbose:
            system.LogError(e)
    return False

# Load url
def LoadUrl(driver, url, verbose = False):
    try:
        driver.get(url)
        return True
    except Exception as e:
        if verbose:
            system.LogError(e)
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

# Parse by request
def ParseByRequest(
    id = None,
    name = None,
    xpath = None,
    link_text = None,
    partial_link_text = None,
    tag_name = None,
    class_name = None,
    css_selector = None):
    from selenium.webdriver.common.by import By
    by_type = None
    by_value = None
    if id:
        by_type = By.ID
        by_value = id
    elif name:
        by_type = By.NAME
        by_value = name
    elif xpath:
        by_type = By.XPATH
        by_value = xpath
    elif link_text:
        by_type = By.LINK_TEXT
        by_value = link_text
    elif partial_link_text:
        by_type = By.PARTIAL_LINK_TEXT
        by_value = partial_link_text
    elif tag_name:
        by_type = By.TAG_NAME
        by_value = tag_name
    elif class_name:
        by_type = By.CLASS_NAME
        by_value = class_name
    elif css_selector:
        by_type = By.CSS_SELECTOR
        by_value = css_selector
    return (by_type, by_value)

# Wait for page elements by class
def WaitForPageElements(
    driver,
    id = None,
    name = None,
    xpath = None,
    link_text = None,
    partial_link_text = None,
    tag_name = None,
    class_name = None,
    css_selector = None,
    wait_time = 1000,
    verbose = False):
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as ExpectedConditions
    try:
        by_type, by_value = ParseByRequest(
            id = id,
            name = name,
            xpath = xpath,
            link_text = link_text,
            partial_link_text = partial_link_text,
            tag_name = tag_name,
            class_name = class_name,
            css_selector = css_selector)
        return WebDriverWait(driver, wait_time).until(
            ExpectedConditions.presence_of_all_elements_located((by_type, by_value))
        )
    except Exception as e:
        if verbose:
            system.LogError(e)
    return None

# Wait for page element by class
def WaitForPageElement(
    driver,
    id = None,
    name = None,
    xpath = None,
    link_text = None,
    partial_link_text = None,
    tag_name = None,
    class_name = None,
    css_selector = None,
    wait_time = 1000,
    verbose = False):
    elements = WaitForPageElements(
        driver = driver,
        id = id,
        name = name,
        xpath = xpath,
        link_text = link_text,
        partial_link_text = partial_link_text,
        tag_name = tag_name,
        class_name = class_name,
        css_selector = css_selector,
        wait_time = wait_time,
        verbose = verbose)
    if isinstance(elements, list) and len(elements) > 0:
        return elements[0]
    return None

# Get element
def GetElement(
    parent,
    id = None,
    name = None,
    xpath = None,
    link_text = None,
    partial_link_text = None,
    tag_name = None,
    class_name = None,
    css_selector = None,
    all_elements = False,
    verbose = False):
    try:
        by_type, by_value = ParseByRequest(
            id = id,
            name = name,
            xpath = xpath,
            link_text = link_text,
            partial_link_text = partial_link_text,
            tag_name = tag_name,
            class_name = class_name,
            css_selector = css_selector)
        if all_elements:
            return parent.find_elements(by_type, by_value)
        else:
            return parent.find_element(by_type, by_value)
    except Exception as e:
        if verbose:
            system.LogError(e)
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
    return system.ExtractWebText(GetElementAttribute(element, "innerHTML"))

# Click element
def ClickElement(element, verbose = False):
    try:
        if element:
            element.click()
    except Exception as e:
        if verbose:
            system.LogError(e)

# Scroll to end of page
def ScrollToEndOfPage(driver, verbose = False):
    try:
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight)")
    except Exception as e:
        if verbose:
            system.LogError(e)

# Get page source
def GetPageSource(driver, url = None, verbose = False):
    try:
        if url:
            driver.get(url)
        return str(driver.page_source)
    except Exception as e:
        if verbose:
            system.LogError(e)
    return None

# Save cookie
def SaveCookie(driver, path, verbose = False):
    if not system.IsPathValid(path):
        return False
    try:
        with open(path, "w") as filehandler:
            json.dump(driver.get_cookies(), filehandler)
        return True
    except Exception as e:
        if verbose:
            system.LogError(e)
    return False

# Load cookie
def LoadCookie(driver, path, verbose = False):
    if not system.DoesPathExist(path):
        return False
    try:
        with open(path, "r") as cookiesfile:
            cookies = json.load(cookiesfile)
        for cookie in cookies:
            driver.add_cookie(cookie)
        return True
    except Exception as e:
        if verbose:
            system.LogError(e)
    return False

###########################################################

# Log into website
def LogIntoWebsite(
    driver,
    login_url,
    cookiefile,
    id = None,
    name = None,
    xpath = None,
    link_text = None,
    partial_link_text = None,
    tag_name = None,
    class_name = None,
    css_selector = None,
    wait_time = 1000,
    verbose = False):

    # Load the login page
    try:
        driver.get(login_url)
    except Exception as e:
        if verbose:
            system.LogError(e)
        return False

    # Look for element
    login_check = WaitForPageElement(
        driver = driver,
        id = id,
        name = name,
        xpath = xpath,
        link_text = link_text,
        partial_link_text = partial_link_text,
        tag_name = tag_name,
        class_name = class_name,
        css_selector = css_selector,
        wait_time = wait_time,
        verbose = verbose)
    if not login_check:
        return False

    # Save cookie
    SaveCookie(driver, cookiefile)
    return True

# Get all matching urls
def GetMatchingUrls(url, base_url, params = {}, starts_with = "", ends_with = "", verbose = False):

    # Get page text
    page_text = ""
    driver = CreateWebDriver(make_headless = True, verbose = verbose)
    if driver:
        page_text = GetPageSource(driver, url, verbose = verbose)
        DestroyWebDriver(driver, verbose = verbose)

    # Fallback for getting page text
    if not page_text or len(page_text) == 0:
        import requests
        reqs = requests.get(url, params=params)
        page_text = reqs.text

    # Find all matching urls
    matching_urls = []
    parser = ParseHtmlPageSource(page_text)
    if parser:
        potential_urls = []
        for link in parser.find_all("a"):
            link_href = link.get("href")
            if not link_href:
                continue
            if not link_href.startswith("http"):
                if base_url.endswith("/"):
                    link_href = system.JoinStringsAsUrl(base_url, link_href)
                else:
                    link_href = system.JoinStringsAsUrl(base_url + "/", link_href)
            if link_href:
                potential_urls.append(link_href)
        for link in parser.find_all(string=re.compile("^http")):
            potential_urls.append(link)
        for potential_url in potential_urls:
            match = re.search("^%s.*%s$" % (starts_with, ends_with), potential_url)
            if match:
                matching_urls.append(potential_url)
    return matching_urls

# Get matching url
def GetMatchingUrl(url, base_url, params = {}, starts_with = "", ends_with = "", get_latest = False, verbose = False):

    # Find potential matching archive urls
    potential_urls = GetMatchingUrls(
        url = url,
        base_url = base_url,
        params = params,
        starts_with = starts_with,
        ends_with = ends_with,
        verbose = verbose)

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
