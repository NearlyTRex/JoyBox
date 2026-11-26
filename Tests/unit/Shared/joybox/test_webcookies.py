# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import webpage
from joybox import webcookies
from webpage_helpers import LOCATOR, FakeDriver, FakeElement

pytest.importorskip("bs4")


###########################################################
# Cookie files
###########################################################

def test_a_cookie_file_is_placed_in_the_cookie_directory(monkeypatch):
    monkeypatch.setattr(webcookies.runtime, "get_cookie_directory", lambda: "/home/user/.cookies")

    assert webcookies.get_cookie_file("gog").startswith("/home/user/.cookies")


def test_a_cookie_file_is_named_after_its_site(monkeypatch):
    monkeypatch.setattr(webcookies.runtime, "get_cookie_directory", lambda: "/cookies")
    path = webcookies.get_cookie_file("gog")

    assert "gog" in path
    assert path.endswith(webcookies.config.COOKIE_SUFFIX_PATH)


def test_two_sites_get_distinct_cookie_files(monkeypatch):
    monkeypatch.setattr(webcookies.runtime, "get_cookie_directory", lambda: "/cookies")

    assert webcookies.get_cookie_file("gog") != webcookies.get_cookie_file("humblebundle")


###########################################################
# Cookies
#
# A saved session is what avoids logging into a store on every scrape.
###########################################################

COOKIES = [
    {"name": "session", "value": "abc123", "domain": ".example.com"},
    {"name": "prefs", "value": "dark", "domain": ".example.com"},
]


def test_cookies_are_saved(tmp_path):
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)
    driver = FakeDriver(cookies = COOKIES)

    assert webcookies.save_cookie(driver, str(target)) is True
    assert json.loads(target.read_text()) == COOKIES


def test_saving_creates_the_cookie_directory(tmp_path):
    target = tmp_path / "nested" / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)
    webcookies.save_cookie(FakeDriver(cookies = COOKIES), str(target))

    assert target.exists()


def test_no_cookies_saves_nothing(tmp_path):
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)

    assert webcookies.save_cookie(FakeDriver(cookies = []), str(target)) is False
    assert not target.exists()


def test_a_dead_session_saves_no_cookies(tmp_path):
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)

    assert webcookies.save_cookie(FakeDriver(dead = True), str(target)) is False
    assert not target.exists()


@pytest.mark.parametrize("path", [None, ""])
def test_an_invalid_cookie_path_is_refused(path):
    assert webcookies.save_cookie(FakeDriver(cookies = COOKIES), path) is False


def test_cookies_are_loaded(tmp_path):
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver()

    assert webcookies.load_cookie(driver, str(target)) is True
    assert driver.added_cookies == COOKIES


def test_a_missing_cookie_file_loads_nothing(tmp_path):
    driver = FakeDriver()

    assert webcookies.load_cookie(driver, str(tmp_path / "absent.cookie")) is False
    assert driver.added_cookies == []


def test_a_cookie_file_that_is_not_a_list_is_refused(tmp_path):
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)
    target.write_text(json.dumps({"name": "session"}))

    assert webcookies.load_cookie(FakeDriver(), str(target)) is False


def test_one_bad_cookie_does_not_stop_the_rest(tmp_path):
    # An expired or malformed cookie should not cost the whole session.
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)
    target.write_text(json.dumps([{"bad": "cookie"}] + COOKIES))
    driver = FakeDriver()

    assert webcookies.load_cookie(driver, str(target)) is True
    assert driver.added_cookies == COOKIES


def test_a_dead_session_loads_no_cookies(tmp_path):
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver(dead = True)

    assert webcookies.load_cookie(driver, str(target)) is False
    assert driver.added_cookies == []


def test_pretending_loads_no_cookies(tmp_path):
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)
    target.write_text(json.dumps(COOKIES))
    driver = FakeDriver()
    webcookies.load_cookie(driver, str(target), pretend_run = True)

    assert driver.added_cookies == []


def test_cookies_survive_a_save_and_load(tmp_path):
    target = tmp_path / ("store" + webcookies.config.COOKIE_SUFFIX_PATH)
    webcookies.save_cookie(FakeDriver(cookies = COOKIES), str(target))
    driver = FakeDriver()
    webcookies.load_cookie(driver, str(target))

    assert driver.added_cookies == COOKIES


###########################################################
# Cookie backed sessions
###########################################################

@pytest.fixture
def session(monkeypatch, tmp_path):
    state = {"loaded": [], "element": FakeElement(text = "signed in"),
             "saved": [], "cookie_loaded": True, "loads_ok": True}

    def load_url(driver, url, *args, **kwargs):
        state["loaded"].append(url)
        return state["loads_ok"]

    monkeypatch.setattr(webpage, "load_url", load_url)
    monkeypatch.setattr(webpage, "wait_for_element", lambda **kwargs: state["element"])
    monkeypatch.setattr(
        webcookies, "save_cookie",
        lambda driver, path, **kwargs: state["saved"].append(path) or True)
    monkeypatch.setattr(webcookies, "load_cookie", lambda **kwargs: state["cookie_loaded"])
    return state


def test_a_login_saves_its_cookie(session):
    assert webcookies.login_cookie_website(
        FakeDriver(), "https://store.example/login", "/cookies/store.pkl", LOCATOR) is True
    assert session["saved"] == ["/cookies/store.pkl"]


def test_a_login_that_never_signed_in_saves_nothing(session):
    # Saving before the login completed writes a cookie that authenticates
    # nobody, and the next run believes it is signed in.
    session["element"] = None

    assert webcookies.login_cookie_website(
        FakeDriver(), "https://store.example/login", "/cookies/store.pkl", LOCATOR) is False
    assert session["saved"] == []


def test_a_login_page_that_will_not_load_saves_nothing(session):
    session["loads_ok"] = False

    assert webcookies.login_cookie_website(
        FakeDriver(), "https://store.example/login", "/cookies/store.pkl", LOCATOR) is False
    assert session["saved"] == []


def test_a_cookie_session_loads_the_page_twice(session):
    # The cookie can only be added once the browser is on the site, and it
    # only takes effect on the next load.
    assert webcookies.load_cookie_website(
        FakeDriver(), "https://store.example/library", "/cookies/store.pkl") is True
    assert session["loaded"] == [
        "https://store.example/library",
        "https://store.example/library",
    ]


def test_a_cookie_that_will_not_load_stops_the_session(session):
    session["cookie_loaded"] = False

    assert webcookies.load_cookie_website(
        FakeDriver(), "https://store.example/library", "/cookies/store.pkl") is False
    assert session["loaded"] == ["https://store.example/library"]


def test_a_cookie_site_that_will_not_load_adds_no_cookie(session):
    session["loads_ok"] = False

    assert webcookies.load_cookie_website(
        FakeDriver(), "https://store.example/library", "/cookies/store.pkl") is False
    assert session["loaded"] == ["https://store.example/library"]


def test_the_generated_cookie_path_is_one_that_can_be_read(tmp_path, monkeypatch):
    # Cookies are written and read as json, and read_json_file refuses a file
    # whose extension does not say so.
    monkeypatch.setattr(webcookies.runtime, "get_cookie_directory", lambda: str(tmp_path))
    target = webcookies.get_cookie_file("steam")

    assert webcookies.save_cookie(FakeDriver(cookies = COOKIES), target) is True
    driver = FakeDriver()
    assert webcookies.load_cookie(driver, target) is True
    assert driver.added_cookies == COOKIES


###########################################################
# Cookie failures
###########################################################

def test_a_verbose_save_writes_the_cookies(tmp_path):
    target = tmp_path / "store.json"

    assert webcookies.save_cookie(FakeDriver(cookies = COOKIES), str(target), verbose = True) is True
    assert json.loads(target.read_text()) == COOKIES


@pytest.mark.parametrize("cookies,path", [([], "store.json"), (COOKIES, "")])
def test_a_verbose_save_with_nothing_to_write_saves_nothing(tmp_path, cookies, path):
    target = str(tmp_path / path) if path else path

    assert webcookies.save_cookie(FakeDriver(cookies = cookies), target, verbose = True) is False


@pytest.mark.parametrize("verbose", [False, True])
def test_a_cookie_directory_that_cannot_be_made_saves_nothing(tmp_path, monkeypatch, verbose):
    monkeypatch.setattr(webcookies.fileops, "make_directory", lambda **kwargs: False)
    target = tmp_path / "store.json"

    assert webcookies.save_cookie(FakeDriver(cookies = COOKIES), str(target), verbose = verbose) is False
    assert not target.exists()


@pytest.mark.parametrize("verbose", [False, True])
def test_cookies_that_cannot_be_written_as_json_are_not_saved(tmp_path, verbose):
    driver = FakeDriver(cookies = [{"name": "session", "value": object()}])

    assert webcookies.save_cookie(driver, str(tmp_path / "store.json"), verbose = verbose) is False


def test_a_failed_save_can_quit_the_program(tmp_path):
    driver = FakeDriver(cookies = [{"name": "session", "value": object()}])

    with pytest.raises(SystemExit):
        webcookies.save_cookie(driver, str(tmp_path / "store.json"), exit_on_failure = True)


def test_save_options_are_passed_to_the_file_writes(tmp_path, monkeypatch):
    calls = []

    def record(name):
        def call(**kwargs):
            calls.append((name, kwargs))
            return True
        return call

    monkeypatch.setattr(webcookies.fileops, "make_directory", record("make_directory"))
    monkeypatch.setattr(webcookies.fileops, "touch_file", record("touch_file"))
    target = str(tmp_path / "store.json")

    assert webcookies.save_cookie(
        FakeDriver(cookies = COOKIES), target, pretend_run = True, exit_on_failure = True) is True
    for name, kwargs in calls:
        assert (kwargs["pretend_run"], kwargs["exit_on_failure"]) == (True, True), name


def write_cookies(tmp_path, cookies):
    target = tmp_path / "store.json"
    target.write_text(json.dumps(cookies))
    return str(target)


def test_a_verbose_load_adds_the_cookies(tmp_path):
    driver = FakeDriver()

    assert webcookies.load_cookie(driver, write_cookies(tmp_path, COOKIES), verbose = True) is True
    assert driver.added_cookies == COOKIES


@pytest.mark.parametrize("cookies", [
    [{"bad": "cookie"}, "not a cookie"],
    [],
])
@pytest.mark.parametrize("verbose", [False, True])
def test_a_cookie_file_with_no_usable_cookies_loads_nothing(tmp_path, cookies, verbose):
    # Reporting success here sends the scraper on as if it were signed in.
    driver = FakeDriver()

    assert webcookies.load_cookie(driver, write_cookies(tmp_path, cookies), verbose = verbose) is False
    assert driver.added_cookies == []


def test_pretending_to_load_cookies_succeeds(tmp_path):
    assert webcookies.load_cookie(FakeDriver(), write_cookies(tmp_path, COOKIES), pretend_run = True) is True


def test_a_verbose_missing_cookie_file_loads_nothing(tmp_path):
    assert webcookies.load_cookie(FakeDriver(), str(tmp_path / "absent.json"), verbose = True) is False


def test_a_verbose_cookie_file_that_is_not_a_list_is_refused(tmp_path):
    assert webcookies.load_cookie(FakeDriver(), write_cookies(tmp_path, {"name": "x"}), verbose = True) is False


@pytest.mark.parametrize("verbose", [False, True])
def test_a_cookie_file_that_cannot_be_read_loads_nothing(tmp_path, monkeypatch, verbose):
    def broken(**kwargs):
        raise OSError("disk error")

    monkeypatch.setattr(webcookies.serialization, "read_json_file", broken)

    assert webcookies.load_cookie(FakeDriver(), write_cookies(tmp_path, COOKIES), verbose = verbose) is False


def test_a_failed_cookie_load_can_quit_the_program(tmp_path, monkeypatch):
    def broken(**kwargs):
        raise OSError("disk error")

    monkeypatch.setattr(webcookies.serialization, "read_json_file", broken)

    with pytest.raises(SystemExit):
        webcookies.load_cookie(FakeDriver(), write_cookies(tmp_path, COOKIES), exit_on_failure = True)
