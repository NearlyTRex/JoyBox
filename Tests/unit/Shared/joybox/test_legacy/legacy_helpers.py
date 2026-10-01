# Imports
import json

# Third-party imports
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By

HEIRLOOM = ["/tools/python", "/tools/heirloom"]
SEARCH_URL = "https://www.bigfishgames.com/us/en/games/search.html?platform=150&language=114&search_query="
GAME_URL = "https://www.bigfishgames.com/us/en/games/1234/mystery-case-files/"


def heirloom_list(*games):
    return json.dumps(list(games))


def heirloom_game(uuid, name):
    return {"installer_uuid": uuid, "game_name": name}


###########################################################
# Fake search page
#
# A tree of elements answering the few Selenium calls joybox.webpage makes,
# so the real element lookups run against it.
###########################################################

class FakeElement:

    def __init__(self, classes = "", tag = "div", attrs = None, children = None):
        self.classes = set(classes.split())
        self.tag = tag
        self.attrs = dict(attrs or {})
        self.children = list(children or [])

    def get_attribute(self, name):
        return self.attrs.get(name)

    def matches(self, by, value):
        if by == By.CLASS_NAME:
            return value in self.classes
        if by == By.TAG_NAME:
            return self.tag == value
        return False

    def walk(self):
        for child in self.children:
            yield child
            yield from child.walk()

    def find_elements(self, by, value):
        return [element for element in self.walk() if element.matches(by, value)]

    def find_element(self, by, value):
        found = self.find_elements(by, value)
        if not found:
            raise NoSuchElementException(value)
        return found[0]


def result_cell(title = "Mystery Case Files", href = GAME_URL + "?src=search"):
    children = []
    if title is not None:
        children.append(FakeElement("productcollection__item-title", attrs = {"innerHTML": "<span>%s</span>" % title}))
    if href is not None:
        children.append(FakeElement(tag = "a", attrs = {"href": href}))
    return FakeElement("productcollection__items", children = children)


class FakeBrowser:

    def __init__(self):
        self.cells = []
        self.has_results = True
        self.connects = []
        self.drivers = []
        self.disconnected = []
        self.loaded = []
        self.waits = []
        self.slept = []
        self.failed_connects = 0
        self.failed_loads = 0

    def add(self, *cells):
        self.cells.extend(cells)

    def connect(self, headless):
        self.connects.append(headless)
        if self.failed_connects:
            self.failed_connects -= 1
            return None
        children = [FakeElement("productcollection__root", children = self.cells)] if self.has_results else []
        driver = FakeElement("page", children = children)
        self.drivers.append(driver)
        return driver

    def load(self, url):
        self.loaded.append(url)
        if self.failed_loads:
            self.failed_loads -= 1
            return False
        return True

    def closed(self):
        return [driver for driver, pretend_run in self.disconnected]
