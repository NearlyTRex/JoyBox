# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import FakeDriver

webdriver = pytest.importorskip("selenium.webdriver")
chrome_service = pytest.importorskip("selenium.webdriver.chrome.service")
chrome_options = pytest.importorskip("selenium.webdriver.chrome.options")
firefox_service = pytest.importorskip("selenium.webdriver.firefox.service")
firefox_options = pytest.importorskip("selenium.webdriver.firefox.options")
chrome_manager = pytest.importorskip("webdriver_manager.chrome")
firefox_manager = pytest.importorskip("webdriver_manager.firefox")



###########################################################
# Browser doubles
#
# The real classes start a browser process; these record what they were
# configured with instead.
###########################################################

class FakeService:

    def __init__(self, executable_path = None, log_output = None, **kwargs):
        self.executable_path = executable_path
        self.log_output = log_output
        self.kwargs = kwargs


class FakeOptions:

    def __init__(self):
        self.arguments = []
        self.preferences = {}
        self.experimental = {}
        self.binary_location = None
        self.profile = None

    def add_argument(self, argument):
        self.arguments.append(argument)

    def set_preference(self, name, value):
        self.preferences[name] = value

    def add_experimental_option(self, name, value):
        self.experimental[name] = value


@pytest.fixture
def browsers(monkeypatch):
    state = {"installed": {"ChromeDriver": "/tools/chromedriver", "GeckoDriver": "/tools/geckodriver"},
             "managed": {"chrome": "/cache/chromedriver", "firefox": "/cache/geckodriver"},
             "programs": {}, "created": [], "error": None, "manager_error": None}

    def browser(kind):
        def create(service = None, options = None):
            if state["error"]:
                raise state["error"]
            created = {"kind": kind, "service": service, "options": options}
            state["created"].append(created)
            return created
        return create

    def manager(kind):
        class FakeManager:
            def install(self):
                if state["manager_error"]:
                    raise state["manager_error"]
                return state["managed"][kind]
        return FakeManager

    def get_tool_program(name):
        return state["installed"].get(name) or state["programs"].get(name)

    monkeypatch.setattr(webpage.programs, "is_tool_installed", lambda name: name in state["installed"])
    monkeypatch.setattr(webpage.programs, "get_tool_program", get_tool_program)
    monkeypatch.setattr(chrome_manager, "ChromeDriverManager", manager("chrome"))
    monkeypatch.setattr(firefox_manager, "GeckoDriverManager", manager("firefox"))
    monkeypatch.setattr(chrome_service, "Service", FakeService)
    monkeypatch.setattr(chrome_options, "Options", FakeOptions)
    monkeypatch.setattr(firefox_service, "Service", FakeService)
    monkeypatch.setattr(firefox_options, "Options", FakeOptions)
    monkeypatch.setattr(webdriver, "Chrome", browser("chrome"))
    monkeypatch.setattr(webdriver, "Firefox", browser("firefox"))
    return state


###########################################################
# Chrome
###########################################################

def test_chrome_runs_the_driver_matching_the_browser(browsers):
    # The driver comes from webdriver_manager so its version follows the
    # installed browser.
    created = webpage.create_chrome_web_driver()

    assert created["kind"] == "chrome"
    assert created["service"].executable_path == "/cache/chromedriver"
    assert created["service"].kwargs == {}


@pytest.mark.parametrize("missing", ["tool", "managed"])
def test_chrome_without_a_driver_is_not_created(browsers, missing):
    if missing == "tool":
        del browsers["installed"]["ChromeDriver"]
    else:
        browsers["manager_error"] = RuntimeError("offline")

    assert webpage.create_chrome_web_driver() is None
    assert browsers["created"] == []


def test_chrome_headless_sets_a_window_size(browsers):
    options = webpage.create_chrome_web_driver(make_headless = True)["options"]

    assert "--headless" in options.arguments
    assert "--window-size=1920,1080" in options.arguments


def test_chrome_shows_a_window_unless_headless(browsers):
    options = webpage.create_chrome_web_driver()["options"]

    assert "--headless" not in options.arguments


def test_chrome_downloads_into_the_requested_directory(browsers, tmp_path):
    options = webpage.create_chrome_web_driver(download_dir = str(tmp_path))["options"]

    assert options.experimental["prefs"]["download.default_directory"] == str(tmp_path)


def test_chrome_uses_the_requested_profile(browsers, tmp_path):
    options = webpage.create_chrome_web_driver(profile_dir = str(tmp_path))["options"]

    assert "--user-data-dir=%s" % tmp_path in options.arguments


def test_chrome_ignores_directories_that_do_not_exist(browsers, tmp_path):
    missing = str(tmp_path / "absent")
    options = webpage.create_chrome_web_driver(
        download_dir = missing, profile_dir = missing, binary_location = missing)["options"]

    assert options.experimental == {}
    assert not any(argument.startswith("--user-data-dir") for argument in options.arguments)
    assert options.binary_location is None


def test_chrome_uses_an_existing_browser_binary(browsers, tmp_path):
    binary = tmp_path / "brave"
    binary.write_text("")
    options = webpage.create_chrome_web_driver(binary_location = str(binary))["options"]

    assert options.binary_location == str(binary)


def test_pretending_creates_no_chrome(browsers):
    assert webpage.create_chrome_web_driver(pretend_run = True, verbose = True) is None
    assert browsers["created"] == []


def test_a_chrome_that_fails_to_start_is_absent(browsers):
    browsers["error"] = RuntimeError("no display")

    assert webpage.create_chrome_web_driver(verbose = True) is None


def test_a_chrome_that_fails_to_start_can_quit_the_program(browsers):
    browsers["error"] = RuntimeError("no display")

    with pytest.raises(SystemExit):
        webpage.create_chrome_web_driver(exit_on_failure = True)


###########################################################
# Firefox
###########################################################

def test_firefox_runs_the_driver_matching_the_browser(browsers):
    created = webpage.create_firefox_web_driver()

    assert created["kind"] == "firefox"
    assert created["service"].executable_path == "/cache/geckodriver"


@pytest.mark.parametrize("missing", ["tool", "managed"])
def test_firefox_without_a_driver_is_not_created(browsers, missing):
    if missing == "tool":
        del browsers["installed"]["GeckoDriver"]
    else:
        browsers["manager_error"] = RuntimeError("offline")

    assert webpage.create_firefox_web_driver() is None
    assert browsers["created"] == []


def test_firefox_downloads_into_the_requested_directory(browsers, tmp_path):
    options = webpage.create_firefox_web_driver(download_dir = str(tmp_path))["options"]

    assert options.preferences["browser.download.folderList"] == 2
    assert options.preferences["browser.download.dir"] == str(tmp_path)


def test_firefox_uses_the_requested_profile(browsers, tmp_path):
    # A "profile" preference does nothing; the profile is an option of its own.
    options = webpage.create_firefox_web_driver(profile_dir = str(tmp_path))["options"]

    assert options.profile == str(tmp_path)
    assert "profile" not in options.preferences


def test_firefox_ignores_directories_that_do_not_exist(browsers, tmp_path):
    missing = str(tmp_path / "absent")
    options = webpage.create_firefox_web_driver(
        download_dir = missing, profile_dir = missing, binary_location = missing)["options"]

    assert options.preferences == {}
    assert options.profile is None
    assert options.binary_location is None


def test_firefox_headless_is_requested(browsers):
    assert "--headless" in webpage.create_firefox_web_driver(make_headless = True)["options"].arguments


def test_firefox_shows_a_window_unless_headless(browsers):
    assert webpage.create_firefox_web_driver()["options"].arguments == []


def test_firefox_uses_an_existing_browser_binary(browsers, tmp_path):
    binary = tmp_path / "firefox"
    binary.write_text("")
    options = webpage.create_firefox_web_driver(binary_location = str(binary))["options"]

    assert options.binary_location == str(binary)


def test_pretending_creates_no_firefox(browsers):
    assert webpage.create_firefox_web_driver(pretend_run = True, verbose = True) is None
    assert browsers["created"] == []


def test_a_firefox_that_fails_to_start_is_absent(browsers):
    browsers["error"] = RuntimeError("no display")

    assert webpage.create_firefox_web_driver(verbose = True) is None


def test_a_firefox_that_fails_to_start_can_quit_the_program(browsers):
    browsers["error"] = RuntimeError("no display")

    with pytest.raises(SystemExit):
        webpage.create_firefox_web_driver(exit_on_failure = True)


###########################################################
# Choosing a browser
###########################################################

@pytest.fixture
def chosen(monkeypatch):
    calls = []

    def recorder(kind):
        def create(**kwargs):
            calls.append((kind, kwargs))
            return kind
        return create

    monkeypatch.setattr(webpage, "create_chrome_web_driver", recorder("chrome"))
    monkeypatch.setattr(webpage, "create_firefox_web_driver", recorder("firefox"))
    programs = {"Firefox": "/bin/firefox", "Chrome": "/bin/chrome", "Brave": "/bin/brave"}
    monkeypatch.setattr(webpage.programs, "get_tool_program", lambda name: programs[name])
    return calls


@pytest.mark.parametrize("driver_type,kind,binary", [
    (webpage.config.WebDriverType.FIREFOX, "firefox", "/bin/firefox"),
    (webpage.config.WebDriverType.CHROME, "chrome", "/bin/chrome"),
    (webpage.config.WebDriverType.BRAVE, "chrome", "/bin/brave"),
])
def test_each_driver_type_starts_its_browser(chosen, driver_type, kind, binary):
    assert webpage.create_web_driver(driver_type = driver_type) == kind
    assert chosen[0][1]["binary_location"] == binary


def test_driver_options_are_passed_through(chosen):
    webpage.create_web_driver(
        driver_type = webpage.config.WebDriverType.FIREFOX,
        download_dir = "/downloads", profile_dir = "/profile", make_headless = True,
        verbose = True, pretend_run = True, exit_on_failure = True)

    assert chosen[0][1] == {
        "download_dir": "/downloads", "profile_dir": "/profile",
        "binary_location": "/bin/firefox", "make_headless": True,
        "verbose": True, "pretend_run": True, "exit_on_failure": True}


@pytest.mark.parametrize("name,kind", [("chrome", "chrome"), ("Brave", "chrome"), ("firefox", "firefox")])
def test_the_configured_driver_type_is_used(chosen, isolated_settings, name, kind):
    isolated_settings.set_value("UserData.Scraping", "web_driver_type", name)

    assert webpage.create_web_driver() == kind


@pytest.mark.parametrize("name", ["", "netscape"])
def test_an_unknown_configured_driver_type_falls_back_to_firefox(chosen, isolated_settings, name):
    isolated_settings.set_value("UserData.Scraping", "web_driver_type", name)

    assert webpage.create_web_driver() == "firefox"


def test_an_unreadable_driver_type_setting_falls_back_to_firefox(chosen, monkeypatch):
    monkeypatch.setattr(webpage.settings, "get_value", lambda *args, **kwargs: None)

    assert webpage.create_web_driver() == "firefox"


def test_an_unsupported_driver_type_creates_nothing(chosen):
    assert webpage.create_web_driver(driver_type = "Opera") is None
    assert chosen == []


###########################################################
# Teardown
###########################################################

def test_a_driver_whose_browser_already_died_is_still_shut_down():
    # close() fails against a dead session; skipping quit() then would leave
    # the driver process running for the rest of the run.
    driver = FakeDriver(dead = True)

    assert webpage.destroy_web_driver(driver, verbose = True) is True
    assert driver.quit_calls == 1


def test_pretending_destroys_nothing():
    driver = FakeDriver()

    assert webpage.destroy_web_driver(driver, pretend_run = True) is True
    assert driver.quit_calls == 0


def test_a_failed_teardown_can_quit_the_program():
    class Stubborn(FakeDriver):
        def quit(self):
            raise RuntimeError("already gone")

    with pytest.raises(SystemExit):
        webpage.destroy_web_driver(Stubborn(), verbose = True, exit_on_failure = True)
