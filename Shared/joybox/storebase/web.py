# Local imports
from joybox import logger
from joybox import webpage
from joybox import webcookies

# Web driver and scraping helpers a store inherits; needs get_name and is_valid_metadata_identifier from the store
class StoreWebMixin:

    # Start a Selenium web driver for scraping the store, headless when asked
    def web_connect(
        self,
        headless = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Create web driver
        return webpage.create_web_driver(
            make_headless = headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Shut down a web driver from web_connect
    def web_disconnect(
        self,
        web_driver,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Destroy web driver
        return webpage.destroy_web_driver(
            driver = web_driver,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Run func(web_driver) on a driver from web_connect and disconnect it afterwards;
    # func's result, or None when connecting or disconnecting fails
    def run_with_web_driver(
        self,
        func,
        headless = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Connect to web
        web_driver = self.web_connect(
            headless = headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not web_driver:
            return None

        # Run, then disconnect whatever the outcome
        result = None
        try:
            result = func(web_driver)
        finally:
            disconnected = self.web_disconnect(
                web_driver = web_driver,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        if not disconnected:
            return None
        return result

    # A headless web driver for one scrape attempt; None in a pretend run that got none, else ScrapeFailed without one
    def connect_scrape_driver(self, verbose = False, pretend_run = False):
        web_driver = self.web_connect(
            headless = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
        if not web_driver:
            if pretend_run:
                return None
            raise webpage.ScrapeFailed("Failed to connect to web driver")
        return web_driver

    # Run scrape_func(web_driver) on a fresh headless driver per attempt with retries,
    # disconnecting the driver between attempts and at the end; the scrape's result
    def scrape_with_retries(self, scrape_func, operation_name, verbose = False, pretend_run = False):

        # Store web driver for cleanup
        web_driver = None

        # Cleanup function
        def cleanup_driver():
            nonlocal web_driver
            if web_driver:
                self.web_disconnect(
                    web_driver = web_driver,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                web_driver = None

        # Scrape function
        def attempt_scrape():
            nonlocal web_driver
            web_driver = self.connect_scrape_driver(verbose = verbose, pretend_run = pretend_run)
            if not web_driver:
                return None
            return scrape_func(web_driver)

        # Use retry function with cleanup
        try:
            return webpage.retry_scrape(
                func = attempt_scrape,
                cleanup_func = cleanup_driver,
                verbose = verbose,
                operation_name = operation_name)
        finally:
            cleanup_driver()

    # Metadata from scrape_func(web_driver) with retries; None for an invalid identifier.
    # store_label names the store in the retry log
    def scrape_latest_metadata(self, identifier, scrape_func, store_label, verbose = False, pretend_run = False):
        if not self.is_valid_metadata_identifier(identifier):
            logger.log_warning("Metadata identifier '%s' was not valid" % identifier)
            return None
        return self.scrape_with_retries(
            scrape_func = scrape_func,
            operation_name = "%s metadata fetch for '%s'" % (store_label, identifier),
            verbose = verbose,
            pretend_run = pretend_run)

    # Load a page to scrape; ScrapeFailed when it does not load
    def load_scrape_page(self, web_driver, url):
        if not webpage.load_url(web_driver, url):
            raise webpage.ScrapeFailed("Failed to load URL: %s" % url)

    # Children text of the element matching locator_attrs once the page shows it; None when it never does
    def wait_for_page_text(self, web_driver, locator_attrs, verbose = False):
        element = webpage.wait_for_element(
            driver = web_driver,
            locator = webpage.ElementLocator(locator_attrs),
            verbose = verbose,
            exit_on_failure = False)
        if not element:
            return None
        return webpage.get_element_children_text(element)

    # Saved browser cookie file named after the store
    def get_cookie_file(self):
        return webcookies.get_cookie_file(self.get_name().lower())
