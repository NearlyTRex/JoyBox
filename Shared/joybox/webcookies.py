# Browser cookies: saving and restoring a session's cookies, and logging in to
# a site once so later visits reuse its cookies.

# Imports
import json

# Local imports
from joybox import config
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import runtime
from joybox import serialization
from joybox import webpage

# Save cookie
def save_cookie(
    driver,
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not webpage.is_session_valid(driver, verbose):
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
            runtime.quit_program()
        return False

# Load cookie
def load_cookie(
    driver,
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not webpage.is_session_valid(driver, verbose):
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
            if cookies_loaded == 0:
                if verbose:
                    logger.log_warning("LoadCookie: No cookies could be added")
                return False
            if verbose:
                logger.log_info("Successfully loaded %d cookies" % cookies_loaded)
        return True
    except Exception as e:
        if verbose:
            logger.log_warning("LoadCookie: Failed to load cookies: %s" % str(e))
        if exit_on_failure:
            logger.log_error("Unable to load cookies")
            logger.log_error(e)
            runtime.quit_program()
        return False

# Get cookie file
def get_cookie_file(base_name):
    cookie_file = base_name + config.COOKIE_SUFFIX_PATH
    cookie_dir = runtime.get_cookie_directory()
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
    success = webpage.load_url(
        driver = driver,
        url = url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Look for element
    login_check = webpage.wait_for_element(
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
    success = webpage.load_url(
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
    success = webpage.load_url(
        driver = driver,
        url = url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success
