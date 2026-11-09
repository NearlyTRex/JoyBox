# Imports
import os

# Third-party imports
import psutil
import pytest

# Local imports
from joybox import config
from joybox import webpage

###########################################################
# Real browsers
#
# Each scrape starts a headless browser and destroys it; a browser that
# outlives its driver piles up one per game until memory runs out. Brave's
# launcher script runs the browser as its child, which a driver quit alone
# leaves running.
###########################################################

def running_descendants():
    return [" ".join(child.cmdline()) for child in psutil.Process(os.getpid()).children(recursive = True)
        if child.status() != psutil.STATUS_ZOMBIE]


# What is still running after each of two browsers is started, used and destroyed
def leftovers_after_browsing(driver_type):
    leftovers = []
    for _ in range(2):
        driver = webpage.create_web_driver(driver_type = driver_type, make_headless = True)
        loaded = driver is not None and webpage.load_url(driver, "about:blank")
        destroyed = webpage.destroy_web_driver(driver)
        leftovers.append((loaded, destroyed, running_descendants(), sorted(webpage.running_browser_groups)))
    return leftovers


CLEAN = [(True, True, [], [])] * 2


@pytest.mark.allow_network
@pytest.mark.requires_tool("ChromeDriver", "Brave")
def test_a_destroyed_brave_leaves_nothing_running():
    assert leftovers_after_browsing(config.WebDriverType.BRAVE) == CLEAN


@pytest.mark.allow_network
@pytest.mark.requires_tool("ChromeDriver", "Chrome")
def test_a_destroyed_chrome_leaves_nothing_running():
    assert leftovers_after_browsing(config.WebDriverType.CHROME) == CLEAN


@pytest.mark.allow_network
@pytest.mark.requires_tool("GeckoDriver", "Firefox")
def test_a_destroyed_firefox_leaves_nothing_running():
    assert leftovers_after_browsing(config.WebDriverType.FIREFOX) == CLEAN
