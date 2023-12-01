# Imports
import os, os.path
import sys
import pickle
import json
import re

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import programs
import environment
import system

# Create web driver
def CreateWebDriver(download_dir = None, make_headless = False, verbose = False):
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver import Firefox
    try:
        service = FirefoxService(programs.GetToolProgram("GeckoDriver"), log_path=os.path.devnull)
        options = FirefoxOptions()
        if download_dir and os.path.isdir(download_dir):
            options.set_preference("browser.download.folderList", 2)
            options.set_preference("browser.download.dir", download_dir)
        if make_headless:
            options.headless = True
        options.binary_location = command.GetRunnableCommandPath(
            config.default_firefox_exe,
            config.default_firefox_install_dirs)
        return Firefox(service=service, options=options)
    except Exception as e:
        if verbose:
            print(e)
    return None

# Destroy web driver
def DestroyWebDriver(driver, verbose = False):
    try:
        if driver:
            driver.quit()
    except Exception as e:
        if verbose:
            print(e)

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

# Wait for page element by class
def WaitForPageElement(driver, class_name = None, id_name = None, tag_name = None, link_text = None, all_elements = False, wait_time = 1000, verbose = False):
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as ExpectedConditions
    try:
        by_type, by_value = ParseByRequest(class_name, id_name, tag_name, link_text)
        if all_elements:
            return WebDriverWait(driver, wait_time).until(
                ExpectedConditions.presence_of_elements_located((by_type, by_value))
            )
        else:
            return WebDriverWait(driver, wait_time).until(
                ExpectedConditions.presence_of_element_located((by_type, by_value))
            )
    except Exception as e:
        if verbose:
            print(e)
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
            print(e)
    return None

# Get element text
def GetElementText(element):
    try:
        if element:
            return element.text
    except:
        pass
    return None

# Click element
def ClickElement(element):
    try:
        if element:
            element.click()
    except:
        pass

# Get page source
def GetPageSource(driver, url, verbose = False):
    try:
        driver.get(url)
        return str(driver.page_source)
    except Exception as e:
        if verbose:
            print(e)
    return None

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

# Get all matching urls
def GetMatchingUrls(url, params = {}, starts_with = "", ends_with = "", verbose = False):

    # Get page text
    page_text = ""
    try:
        web_driver = CreateWebDriver(make_headless = True, verbose = verbose)
        if web_driver:
            page_text = GetPageSource(web_driver, url, verbose = verbose)
            DestroyWebDriver(web_driver, verbose = verbose)
    except Exception as e:
        if verbose:
            print(e)

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
            link_href = os.path.dirname(url) + "/" + link_href
        match = re.search("^%s.*%s$" % (starts_with, ends_with), link_href)
        if match:
            matching_urls.append(link_href)
    return matching_urls

# Get matching url
def GetMatchingUrl(url, params = {}, starts_with = "", ends_with = "", get_latest = False, verbose = False):

    # Find potential matching archive urls
    potential_urls = GetMatchingUrls(
        url = url,
        params = params,
        starts_with = starts_with,
        ends_with = ends_with,
        verbose = verbose)

    # Did not find any matching release
    if len(potential_urls) == 0:
        return None

    # Find the latest possible url
    matching_url = potential_urls[0]
    if get_latest:
        potential_map = {}
        for potential_url in potential_urls:
            url_tokens = potential_url.split("/")
            if len(url_tokens) > 0:
                potential_map[url_tokens[-1]] = potential_url
        for potential_key in sorted(potential_map.keys(), reverse = True):
            matching_url = potential_map[potential_key]
            break
    return matching_url
