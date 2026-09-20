###########################################################
# Doubles for the browser
#
# A scrape runs against a browser that can die mid-run, and against elements
# that go stale the moment the page re-renders. Both failures are what the
# helpers under test have to survive, so both are what these fake.
###########################################################

class FakeElement:

    def __init__(self, text = "", attributes = None):
        self.text = text
        self.attributes = attributes or {}

    def get_attribute(self, name):
        return self.attributes.get(name)


class BrokenElement:

    @property
    def text(self):
        raise RuntimeError("stale element")

    def get_attribute(self, name):
        raise RuntimeError("stale element")


class FakeDriver:

    def __init__(self, url = "https://example.com/", cookies = None, dead = False):
        self._url = url
        self._cookies = cookies if cookies is not None else []
        self.dead = dead
        self.visited = []
        self.scripts = []
        self.added_cookies = []
        self.quit_calls = 0
        self.page_source = "<html><body>page</body></html>"

    @property
    def current_url(self):
        if self.dead:
            raise RuntimeError("session deleted")
        return self._url

    def get(self, url):
        if self.dead:
            raise RuntimeError("session deleted")
        self.visited.append(url)
        self._url = url

    def get_cookies(self):
        if self.dead:
            raise RuntimeError("session deleted")
        return self._cookies

    def add_cookie(self, cookie):
        if not isinstance(cookie, dict) or "name" not in cookie:
            raise ValueError("bad cookie")
        self.added_cookies.append(cookie)

    def execute_script(self, script):
        if self.dead:
            raise RuntimeError("session deleted")
        self.scripts.append(script)

    def close(self):
        if self.dead:
            raise RuntimeError("session deleted")

    def quit(self):
        self.quit_calls += 1


class FakeParent:

    # Stands in for a driver or an element that elements are looked up under.
    def __init__(self, found = None, error = None):
        self.found = found
        self.error = error
        self.lookups = []

    @property
    def current_url(self):
        return "https://example.com/"

    def find_element(self, strategy, value):
        self.lookups.append((strategy, value))
        if self.error:
            raise self.error
        return self.found

    def find_elements(self, strategy, value):
        self.lookups.append((strategy, value))
        if self.error:
            raise self.error
        return self.found if isinstance(self.found, list) else [self.found]


class ClickableElement:

    def __init__(self, error = None):
        self.error = error
        self.clicks = 0
        self.keys = []

    def click(self):
        if self.error:
            raise self.error
        self.clicks += 1

    def send_keys(self, keys):
        if self.error:
            raise self.error
        self.keys.append(keys)
