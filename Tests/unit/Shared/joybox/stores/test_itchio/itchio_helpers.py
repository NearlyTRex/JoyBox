# Imports
import re

# Third-party imports
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By

GAME_URL = "https://maker.itch.io/cool-game"


###########################################################
# Fake page
#
# A tree of elements answering the few Selenium calls joybox.webpage makes,
# so the real element lookups run against it.
###########################################################

class FakeElement:

    def __init__(self, classes = "", text = None, attrs = None, children = None):
        self.classes = set(classes.split())
        self.text = text
        self.attrs = dict(attrs or {})
        self.children = list(children or [])
        self.clicks = 0

    def get_attribute(self, name):
        return self.attrs.get(name)

    def click(self):
        self.clicks += 1

    def matches(self, by, value):
        if by == By.CLASS_NAME:
            return value in self.classes
        if by == By.XPATH:
            wanted = re.search(r"contains\(text\(\), '([^']*)'\)", value)
            return bool(wanted) and self.text is not None and wanted.group(1) in self.text
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


class FakeBrowser:

    def __init__(self):
        self.page = FakeElement("page")
        self.connects = []
        self.disconnected = []
        self.loaded = []
        self.login_locators = []
        self.slept = []
        self.scrolls = 0
        self.loader_scrolls = 0
        self.connect_ok = True
        self.disconnect_ok = True
        self.load_ok = True
        self.login_ok = True
        self.load_error = None

    def add(self, element):
        self.page.children.append(element)
        return element

    def add_loader(self, scrolls):
        self.loader_scrolls = scrolls
        self.add(FakeElement("grid_loader"))

    def load(self, url, cookie):
        self.loaded.append((url, cookie))
        if self.load_error:
            raise self.load_error

    def scroll(self):
        self.scrolls += 1
        if self.scrolls >= self.loader_scrolls:
            self.page.children = [child for child in self.page.children if "grid_loader" not in child.classes]


def game_cell(url = GAME_URL, title = "Cool Game", cover = "https://img.itch.zone/cover.png", game_id = "1234"):
    children = []
    if title is not None:
        attrs = {"href": url} if url is not None else {}
        children.append(FakeElement("title game_link", text = title, attrs = attrs))
    if cover is not None:
        children.append(FakeElement("lazy_loaded", attrs = {"src": cover}))
    return FakeElement("game_cell", attrs = {"data-game_id": game_id}, children = children)
