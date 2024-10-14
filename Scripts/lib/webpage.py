# Imports
import os, os.path
import sys
import pickle
import json
import re
import urllib.parse

# Local imports
import config
import command
import programs
import environment
import system

# Create web driver
def CreateWebDriver(download_dir = None, profile_dir = None, make_headless = False, verbose = False):
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
            options.headless = True
        options.binary_location = programs.GetToolProgram("Firefox")
        return Firefox(service=service, options=options)
    except Exception as e:
        if verbose:
            system.LogError(e)
    return None

# Destroy web driver
def DestroyWebDriver(driver, verbose = False):
    try:
        if driver:
            driver.quit()
    except Exception as e:
        if verbose:
            system.LogError(e)

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
def ParseByRequest(class_name = None, id_name = None, tag_name = None, link_text = None):
    from selenium.webdriver.common.by import By
    by_type = None
    by_value = None
    if class_name:
        by_type = By.CLASS_NAME
        by_value = class_name
    elif id_name:
        by_type = By.ID
        by_value = id_name
    elif tag_name:
        by_type = By.TAG_NAME
        by_value = tag_name
    elif link_text:
        by_type = By.LINK_TEXT
        by_value = link_text
    return (by_type, by_value)

# Wait for page elements by class
def WaitForPageElements(driver, class_name = None, id_name = None, tag_name = None, link_text = None, wait_time = 1000, verbose = False):
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as ExpectedConditions
    try:
        by_type, by_value = ParseByRequest(class_name, id_name, tag_name, link_text)
        return WebDriverWait(driver, wait_time).until(
            ExpectedConditions.presence_of_all_elements_located((by_type, by_value))
        )
    except Exception as e:
        if verbose:
            system.LogError(e)
    return None

# Wait for page element by class
def WaitForPageElement(driver, class_name = None, id_name = None, tag_name = None, link_text = None, wait_time = 1000, verbose = False):
    elements = WaitForPageElements(
        driver = driver,
        class_name = class_name,
        id_name = id_name,
        tag_name = tag_name,
        link_text = link_text,
        wait_time = wait_time,
        verbose = verbose)
    if len(elements) > 0:
        return elements[0]
    return None

# Get element
def GetElement(parent, class_name = None, id_name = None, tag_name = None, link_text = None, all_elements = False, verbose = False):
    try:
        by_type, by_value = ParseByRequest(class_name, id_name, tag_name, link_text)
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

# Parse page source
def ParsePageSource(html_contents):
    try:
        from BeautifulSoup import BeautifulSoup
    except ImportError:
        from bs4 import BeautifulSoup
    return BeautifulSoup(html_contents, features="lxml")

# Save cookie
def SaveCookie(driver, path):
    with open(path, 'w') as filehandler:
        json.dump(driver.get_cookies(), filehandler)

# Load cookie
def LoadCookie(driver, path):
    with open(path, 'r') as cookiesfile:
        cookies = json.load(cookiesfile)
    for cookie in cookies:
        driver.add_cookie(cookie)

# Log into website
def LogIntoWebsite(
    driver,
    login_url,
    cookiefile,
    class_name = None,
    id_name = None,
    tag_name = None,
    link_text = None,
    wait_time = 1000,
    verbose = False):

    # Load the login page
    try:
        driver.get(login_url)
    except Exception as e:
        if verbose:
            system.LogError(e)
        return False

    # Load cookie if it exists
    if os.path.exists(cookiefile):

        # Load cookie
        LoadCookie(driver, cookiefile)
        return True

    # Look for element
    login_check = WaitForPageElement(
        driver = driver,
        class_name = class_name,
        id_name = id_name,
        tag_name = tag_name,
        link_text = link_text,
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
    try:
        driver = CreateWebDriver(make_headless = True, verbose = verbose)
        if driver:
            page_text = GetPageSource(driver, url, verbose = verbose)
            DestroyWebDriver(driver, verbose = verbose)
    except Exception as e:
        if verbose:
            system.LogError(e)

    # Fallback for getting page text
    if not page_text or len(page_text) == 0:
        import requests
        reqs = requests.get(url, params=params)
        page_text = reqs.text

    # Parse page text
    import bs4
    parser = bs4.BeautifulSoup(page_text, "html.parser")

    # Find all matching urls
    matching_urls = []
    for link in parser.find_all("a"):
        link_href = link.get("href")
        if not link_href:
            continue
        if not link_href.startswith("http"):
            if base_url.endswith("/"):
                link_href = urllib.parse.urljoin(base_url, link_href)
            else:
                link_href = urllib.parse.urljoin(base_url + "/", link_href)
        match = re.search("^%s.*%s$" % (starts_with, ends_with), link_href)
        if match:
            matching_urls.append(link_href)
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
