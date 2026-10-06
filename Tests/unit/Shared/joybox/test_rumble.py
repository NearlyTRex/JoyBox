# Imports
import pytest

# Local imports
from joybox import rumble


###########################################################
# Rumble channel enumeration
###########################################################

def video_json(*slugs):
    return "".join(
        '{"url":"https://rumble.com/%s-some-title.html"}' % slug for slug in slugs)


@pytest.fixture
def curl(monkeypatch):
    monkeypatch.setattr(rumble.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(rumble.programs, "get_tool_program", lambda name: "/tools/curl")


@pytest.fixture
def pages(monkeypatch):
    # Serves page N of a channel from a list; past the end, a body with no videos
    fetched = []
    served = []

    def fetch_channel_page(page_url, **kwargs):
        fetched.append(page_url)
        index = len(fetched) - 1
        return served[index] if index < len(served) else "<html>404</html>"

    monkeypatch.setattr(rumble, "fetch_channel_page", fetch_channel_page)
    return served, fetched


@pytest.mark.parametrize("url", [
    "https://rumble.com/c/c-2666954",
    "https://www.rumble.com/c/ChannelName/",
    "http://rumble.com/user/SomeUser",
    "  https://RUMBLE.com/c/Name  ",
])
def test_channel_and_user_pages_are_recognised(url):
    assert rumble.is_rumble_channel_url(url) is True


@pytest.mark.parametrize("url", [
    "",
    None,
    "https://rumble.com/v2fyso2-a-video.html",
    "https://rumble.com/c/Name/videos",
    "https://example.com/c/Name",
])
def test_other_urls_are_not_channels(url):
    assert rumble.is_rumble_channel_url(url) is False


def test_fetching_a_page_uses_curl_with_a_browser_user_agent(curl, recording_command):
    recording_command.output = "<html/>"

    assert rumble.fetch_channel_page("https://rumble.com/c/Name?page=2") == "<html/>"
    assert recording_command.value_after("-A") == rumble.USER_AGENT
    assert recording_command.only()[-1] == "https://rumble.com/c/Name?page=2"
    assert "/tools/curl" in recording_command.options().get_blocking_processes()


def test_fetching_without_curl_returns_nothing(monkeypatch, recording_command):
    monkeypatch.setattr(rumble.programs, "is_tool_installed", lambda name: False)

    assert rumble.fetch_channel_page("https://rumble.com/c/Name") is None
    assert recording_command.ran() is False


def test_enumeration_pages_until_a_page_adds_nothing(pages):
    served, fetched = pages
    served.extend([video_json("va1", "va2"), video_json("vb1")])

    videos = rumble.get_channel_video_urls("https://rumble.com/c/Name/?sort=new")

    assert videos == [
        ("va1", "https://rumble.com/va1-some-title.html"),
        ("va2", "https://rumble.com/va2-some-title.html"),
        ("vb1", "https://rumble.com/vb1-some-title.html"),
    ]
    assert fetched == [
        "https://rumble.com/c/Name?page=1",
        "https://rumble.com/c/Name?page=2",
        "https://rumble.com/c/Name?page=3",
    ]


def test_a_video_repeated_across_pages_is_listed_once(pages):
    served, fetched = pages
    served.extend([video_json("va1", "va1"), video_json("va1")])

    assert rumble.get_channel_video_urls("https://rumble.com/c/Name") == [
        ("va1", "https://rumble.com/va1-some-title.html")]
    assert len(fetched) == 2


def test_an_empty_fetch_stops_enumeration(pages):
    served, fetched = pages
    served.extend([video_json("va1"), ""])

    assert len(rumble.get_channel_video_urls("https://rumble.com/c/Name")) == 1
    assert len(fetched) == 2


def test_enumeration_stops_at_the_page_cap(pages, monkeypatch):
    served, fetched = pages
    monkeypatch.setattr(rumble, "MAX_CHANNEL_PAGES", 2)
    served.extend([video_json("va1"), video_json("vb1"), video_json("vc1")])

    assert [video_id for video_id, _ in rumble.get_channel_video_urls(
        "https://rumble.com/c/Name", verbose = True)] == ["va1", "vb1"]
    assert len(fetched) == 2
