# Imports
import json
import urllib.parse

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import google

YTDLP = "/tools/yt-dlp"

###########################################################
# Fixtures
###########################################################

@pytest.fixture
def ytdlp(monkeypatch):
    monkeypatch.setattr(google.programs, "is_tool_installed", lambda name: name == "YtDlp")
    monkeypatch.setattr(google.programs, "get_tool_program", lambda name: YTDLP if name == "YtDlp" else None)
    return YTDLP


@pytest.fixture
def no_ytdlp(monkeypatch):
    monkeypatch.setattr(google.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(google.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def no_js_runtime(monkeypatch):
    monkeypatch.setattr(google, "get_javascript_runtime_args", lambda: [])


@pytest.fixture
def search_credentials(isolated_settings):
    isolated_settings.set_value("UserData.Scraping", "google_search_engine_id", "engine id")
    isolated_settings.set_value("UserData.Scraping", "google_search_engine_api_key", "key&x")
    return isolated_settings


class FakeRemoteJson:

    def __init__(self, monkeypatch, response):
        self.response = response
        self.calls = []
        monkeypatch.setattr(google.network, "get_remote_json", self)

    def __call__(self, url, **kwargs):
        self.calls.append({"url": url, "kwargs": kwargs})
        return self.response

    def query(self):
        assert len(self.calls) == 1
        return urllib.parse.parse_qs(urllib.parse.urlparse(self.calls[0]["url"]).query)


def image_item(title = "Super Game", link = "https://img.test/a.jpg", mime = "image/jpeg", width = 600, height = 800):
    return {"title": title, "link": link, "mime": mime, "image": {"width": width, "height": height}}


def video_line(**fields):
    return json.dumps(fields)

###########################################################
# get_javascript_runtime_args
###########################################################

def test_javascript_runtime_prefers_bootstrap_deno(monkeypatch, tmp_path):
    deno = tmp_path / ".deno" / "bin" / "deno"
    deno.parent.mkdir(parents = True)
    deno.write_text("")
    monkeypatch.setattr(google.paths, "expand_path", lambda path: str(deno))
    monkeypatch.setattr(google.shutil, "which", lambda name: "/usr/bin/deno")
    assert google.get_javascript_runtime_args() == ["--js-runtimes", "deno:%s" % deno]


def test_javascript_runtime_falls_back_to_deno_on_path(monkeypatch, tmp_path):
    deno = tmp_path / "deno"
    deno.write_text("")
    monkeypatch.setattr(google.paths, "expand_path", lambda path: str(tmp_path / "missing"))
    monkeypatch.setattr(google.shutil, "which", lambda name: str(deno))
    assert google.get_javascript_runtime_args() == ["--js-runtimes", "deno:%s" % deno]


def test_javascript_runtime_is_omitted_when_no_deno_exists(monkeypatch, tmp_path):
    monkeypatch.setattr(google.paths, "expand_path", lambda path: str(tmp_path / "missing"))
    monkeypatch.setattr(google.shutil, "which", lambda name: None)
    assert google.get_javascript_runtime_args() == []

###########################################################
# get_cookie_args
###########################################################

def test_cookie_file_is_passed_as_cookies(tmp_path):
    cookies = tmp_path / "cookies.txt"
    cookies.write_text("")
    assert google.get_cookie_args(str(cookies)) == ["--cookies", str(cookies)]


def test_cookie_source_that_is_not_a_file_names_a_browser():
    assert google.get_cookie_args("firefox") == ["--cookies-from-browser", "firefox"]


@pytest.mark.parametrize("cookie_source", [None, "", 5])
def test_missing_cookie_source_adds_no_args(cookie_source):
    assert google.get_cookie_args(cookie_source) == []

###########################################################
# find_images
###########################################################

def test_find_images_without_credentials_returns_empty_list_without_searching(isolated_settings, monkeypatch):
    remote = FakeRemoteJson(monkeypatch, {"items": [image_item()]})
    assert google.find_images("Super Game") == []
    assert remote.calls == []


def test_find_images_builds_an_encoded_search_url(search_credentials, monkeypatch):
    remote = FakeRemoteJson(monkeypatch, {})
    google.find_images(
        "Super Game: Part 2",
        image_type = config.ImageFileType.JPEG,
        image_size = config.SizeType.LARGE,
        verbose = True,
        pretend_run = True,
        exit_on_failure = True)
    query = remote.query()
    assert query["q"] == ["Super Game: Part 2"]
    assert query["searchType"] == ["image"]
    assert query["fileType"] == ["jpg"]
    assert query["imgSize"] == ["large"]
    assert query["cx"] == ["engine id"]
    assert query["key"] == ["key&x"]
    assert remote.calls[0]["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_find_images_accepts_type_and_size_names(search_credentials, monkeypatch):
    remote = FakeRemoteJson(monkeypatch, {})
    google.find_images("Super Game", image_type = "PNG", image_size = "Small")
    query = remote.query()
    assert query["fileType"] == ["png"]
    assert query["imgSize"] == ["small"]


def test_find_images_omits_unknown_type_and_size(search_credentials, monkeypatch):
    remote = FakeRemoteJson(monkeypatch, {})
    google.find_images("Super Game", image_type = "BMP", image_size = "Huge")
    query = remote.query()
    assert "fileType" not in query
    assert "imgSize" not in query


@pytest.mark.parametrize("requested, sent", [(20, "10"), (3, "3"), (0, "1"), ("bad", "10")])
def test_find_images_clamps_result_count_to_api_limit(search_credentials, monkeypatch, requested, sent):
    remote = FakeRemoteJson(monkeypatch, {})
    google.find_images("Super Game", num_results = requested)
    assert remote.query()["num"] == [sent]


@pytest.mark.parametrize("response", [None, [], "error", {}])
def test_find_images_failed_or_empty_response_returns_empty_list(search_credentials, monkeypatch, response):
    FakeRemoteJson(monkeypatch, response)
    assert google.find_images("Super Game") == []


@pytest.mark.parametrize("items", [None, "items", {"title": "Super Game"}])
def test_find_images_ignores_malformed_items_container(search_credentials, monkeypatch, items):
    FakeRemoteJson(monkeypatch, {"items": items})
    assert google.find_images("Super Game") == []


def test_find_images_returns_similar_images_most_relevant_first(search_credentials, monkeypatch):
    FakeRemoteJson(monkeypatch, {"items": [
        image_item(title = "Super Gamez", link = "https://img.test/near.png", mime = "image/png"),
        image_item(title = "Completely Different", link = "https://img.test/other.jpg"),
        image_item(title = "Super Game", link = "https://img.test/exact.jpg", width = "640", height = "480"),
    ]})
    results = google.find_images("Super Game")
    assert [result.get_url() for result in results] == ["https://img.test/exact.jpg", "https://img.test/near.png"]
    exact = results[0]
    assert exact.get_title() == "Super Game"
    assert exact.get_mime() == "image/jpeg"
    assert (exact.get_width(), exact.get_height()) == (640, 480)
    assert exact.get_relevance() == 100
    assert results[1].get_relevance() < 100


@pytest.mark.parametrize("item", [
    "not a dict",
    {"link": "https://img.test/a.jpg", "image": {"width": 1, "height": 1}},
    {"title": "Super Game", "image": {"width": 1, "height": 1}},
    {"title": "Super Game", "link": "", "image": {"width": 1, "height": 1}},
    {"title": "Super Game", "link": "https://img.test/a.jpg"},
    {"title": "Super Game", "link": "https://img.test/a.jpg", "image": {"width": None, "height": 1}},
    {"title": "Super Game", "link": "https://img.test/a.jpg", "image": {"width": "wide", "height": 1}},
])
def test_find_images_skips_malformed_items_and_keeps_valid_ones(search_credentials, monkeypatch, item):
    FakeRemoteJson(monkeypatch, {"items": [item, image_item()]})
    results = google.find_images("Super Game")
    assert [result.get_url() for result in results] == ["https://img.test/a.jpg"]


def test_find_images_without_mime_still_returns_result(search_credentials, monkeypatch):
    item = image_item()
    del item["mime"]
    FakeRemoteJson(monkeypatch, {"items": [item]})
    results = google.find_images("Super Game")
    assert len(results) == 1
    assert results[0].get_mime() is None


def test_find_images_keeps_only_requested_dimensions(search_credentials, monkeypatch):
    FakeRemoteJson(monkeypatch, {"items": [
        image_item(link = "https://img.test/wrong.jpg", width = 600, height = 600),
        image_item(link = "https://img.test/right.jpg", width = 600, height = 800),
    ]})
    results = google.find_images("Super Game", image_dimensions = ("600", 800))
    assert [result.get_url() for result in results] == ["https://img.test/right.jpg"]


@pytest.mark.parametrize("dimensions", [None, "600x800", (600,), (600, 800, 1), ("wide", "tall"), 7])
def test_find_images_ignores_unusable_dimension_filters(search_credentials, monkeypatch, dimensions):
    FakeRemoteJson(monkeypatch, {"items": [image_item(width = 1, height = 1)]})
    assert len(google.find_images("Super Game", image_dimensions = dimensions)) == 1


def test_find_images_accepts_dimension_generators(search_credentials, monkeypatch):
    FakeRemoteJson(monkeypatch, {"items": [image_item(width = 600, height = 800)]})
    assert len(google.find_images("Super Game", image_dimensions = (x for x in [600, 800]))) == 1

###########################################################
# find_videos
###########################################################

def test_find_videos_without_ytdlp_returns_empty_list(no_ytdlp, recording_command):
    assert google.find_videos("Super Game trailer") == []
    assert not recording_command.ran()


def test_find_videos_runs_search_as_argument_list_without_shell(ytdlp, recording_command):
    google.find_videos("Game \"$(rm -rf ~)\"; & echo", num_results = 5, verbose = True, pretend_run = True, exit_on_failure = True)
    cmd = recording_command.only()
    assert cmd[0] == YTDLP
    assert cmd[1] == "ytsearch5:Game \"$(rm -rf ~)\"; & echo"
    assert "--dump-json" in cmd
    options = recording_command.options()
    assert not options.is_shell()
    assert options.get_blocking_processes() == [YTDLP]
    assert recording_command.calls[0]["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


@pytest.mark.parametrize("requested, sent", [(0, "ytsearch1:"), ("bad", "ytsearch20:"), (None, "ytsearch20:")])
def test_find_videos_normalizes_result_count(ytdlp, recording_command, requested, sent):
    google.find_videos("Super Game", num_results = requested)
    assert recording_command.only()[1] == sent + "Super Game"


@pytest.mark.parametrize("output", ["", None])
def test_find_videos_with_no_output_returns_empty_list(ytdlp, recording_command, output):
    recording_command.output = output
    assert google.find_videos("Super Game") == []


def test_find_videos_returns_similar_videos_shortest_first(ytdlp, recording_command):
    recording_command.output = "\n".join([
        video_line(title = "Super Game trailer", channel = "Studio", duration = 120, duration_string = "2:00", url = "https://yt.test/long"),
        "not json",
        "",
        "[1, 2]",
        video_line(title = "Unrelated cooking show", url = "https://yt.test/other", duration = 5),
        video_line(title = "Super Game trailers", url = "https://yt.test/short", duration = 30.5),
    ])
    results = google.find_videos("Super Game trailer")
    assert [result.get_url() for result in results] == ["https://yt.test/short", "https://yt.test/long"]
    assert results[0].get_description() == "Super Game trailers (Unknown) [Unknown]"
    assert results[0].get_duration() == 30.5
    assert results[1].get_title() == "Super Game trailer"
    assert results[1].get_description() == "Super Game trailer (Studio) [2:00]"
    assert results[1].get_duration() == 120


@pytest.mark.parametrize("duration", [None, "", "1:00", True, [3]])
def test_find_videos_treats_non_numeric_duration_as_zero(ytdlp, recording_command, duration):
    recording_command.output = "\n".join([
        video_line(title = "Super Game", url = "https://yt.test/b", duration = 10),
        video_line(title = "Super Game", url = "https://yt.test/a", duration = duration, channel = None, duration_string = None),
    ])
    results = google.find_videos("Super Game")
    assert [result.get_url() for result in results] == ["https://yt.test/a", "https://yt.test/b"]
    assert results[0].get_duration() == 0
    assert results[0].get_description() == "Super Game (Unknown) [Unknown]"


@pytest.mark.parametrize("fields", [
    {"url": "https://yt.test/a"},
    {"title": None, "url": "https://yt.test/a"},
    {"title": "Super Game"},
    {"title": "Super Game", "url": ""},
    {"title": "Super Game", "url": 5},
])
def test_find_videos_skips_entries_without_title_or_url(ytdlp, recording_command, fields):
    recording_command.output = video_line(**fields)
    assert google.find_videos("Super Game") == []

###########################################################
# get_playlist_video_ids
###########################################################

def test_rumble_channels_use_the_rumble_enumerator(monkeypatch, no_ytdlp, recording_command):
    calls = []
    def get_channel_video_urls(url, **kwargs):
        calls.append((url, kwargs))
        return [("v1", "https://rumble.com/v1.html")]
    monkeypatch.setattr(google.rumble, "get_channel_video_urls", get_channel_video_urls)
    videos = google.get_playlist_video_ids("https://rumble.com/c/SomeChannel", verbose = True, pretend_run = True, exit_on_failure = True)
    assert videos == [("v1", "https://rumble.com/v1.html")]
    assert calls == [("https://rumble.com/c/SomeChannel", {"verbose": True, "pretend_run": True, "exit_on_failure": True})]
    assert not recording_command.ran()


def test_playlist_without_ytdlp_returns_empty_list(no_ytdlp, recording_command):
    assert google.get_playlist_video_ids("https://www.youtube.com/@chan") == []
    assert not recording_command.ran()


def test_playlist_enumerates_ids_and_urls_without_downloading(ytdlp, recording_command):
    google.get_playlist_video_ids("https://www.youtube.com/@chan", cookie_source = "chrome", verbose = True, pretend_run = True, exit_on_failure = True)
    cmd = recording_command.only()
    assert cmd[:4] == [YTDLP, "--flat-playlist", "--print", "%(id)s\t%(url)s"]
    assert recording_command.value_after("--cookies-from-browser") == "chrome"
    assert cmd[-1] == "https://www.youtube.com/@chan"
    assert recording_command.options().get_blocking_processes() == [YTDLP]
    assert recording_command.calls[0]["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_playlist_parses_unique_ids_in_order(ytdlp, recording_command):
    recording_command.output = "\n".join([
        "a\thttps://yt.test/a",
        "b",
        "",
        "a\thttps://yt.test/dup",
        " c \t https://yt.test/c ",
    ])
    videos = google.get_playlist_video_ids("https://www.youtube.com/@chan")
    assert videos == [("a", "https://yt.test/a"), ("b", ""), ("c", "https://yt.test/c")]


def test_playlist_treats_ytdlp_missing_field_marker_as_absent(ytdlp, recording_command):
    recording_command.output = "a\tNA\nNA\thttps://yt.test/x"
    assert google.get_playlist_video_ids("https://www.youtube.com/@chan") == [("a", "")]


@pytest.mark.parametrize("output", ["", None])
def test_playlist_with_no_output_returns_empty_list(ytdlp, recording_command, output):
    recording_command.output = output
    assert google.get_playlist_video_ids("https://www.youtube.com/@chan") == []

###########################################################
# download_video
###########################################################

class FileWritingCommand:

    def __init__(self, monkeypatch, returncode = 0, writes = None):
        self.calls = []
        self.returncode = returncode
        self.writes = writes or []
        monkeypatch.setattr(google.command, "run_returncode_command", self)

    def __call__(self, cmd, options = None, **kwargs):
        self.calls.append({"cmd": list(cmd), "options": options, "kwargs": kwargs})
        for path in self.writes:
            path.write_text("")
        return self.returncode

    def only(self):
        assert len(self.calls) == 1
        return self.calls[0]["cmd"]


def test_download_without_ytdlp_fails_without_running(no_ytdlp, recording_command):
    assert google.download_video("https://yt.test/a") is False
    assert not recording_command.ran()


@pytest.mark.parametrize("video_url", [None, "", [], ["", None]])
def test_download_without_any_url_fails_without_running(ytdlp, recording_command, video_url):
    assert google.download_video(video_url) is False
    assert not recording_command.ran()


def test_download_video_builds_mp4_command(ytdlp, no_js_runtime, recording_command, tmp_path):
    archive = tmp_path / "archive.txt"
    assert google.download_video(
        "https://yt.test/a",
        output_dir = str(tmp_path),
        download_archive = str(archive),
        cookie_source = "firefox") is True
    cmd = recording_command.only()
    assert cmd[0] == YTDLP
    assert recording_command.value_after("--recode-video") == "mp4"
    assert "--extract-audio" not in cmd
    assert recording_command.value_after("-P") == str(tmp_path)
    assert recording_command.value_after("-o") == "%(upload_date)s - %(title).200s.%(ext)s"
    assert recording_command.value_after("--download-archive") == str(archive)
    assert recording_command.value_after("--cookies-from-browser") == "firefox"
    assert "--concurrent-fragments" not in cmd
    assert "--progress" not in cmd
    assert "--simulate" not in cmd
    assert cmd[-1] == "https://yt.test/a"
    assert recording_command.options().get_blocking_processes() == [YTDLP]


def test_download_audio_builds_mp3_command_with_all_targets(ytdlp, no_js_runtime, recording_command):
    google.download_video(("https://yt.test/a", "https://yt.test/b"), audio_only = True, output_file = "/out/song.%(ext)s")
    cmd = recording_command.only()
    assert recording_command.value_after("--audio-format") == "mp3"
    assert "--embed-metadata" in cmd
    assert "--recode-video" not in cmd
    assert "-P" not in cmd
    assert recording_command.value_after("-o") == "/out/song.%(ext)s"
    assert cmd[-2:] == ["https://yt.test/a", "https://yt.test/b"]


def test_download_passes_run_flags_through(ytdlp, no_js_runtime, recording_command):
    google.download_video("https://yt.test/a", verbose = True, pretend_run = True, exit_on_failure = True)
    cmd = recording_command.only()
    assert "--progress" in cmd
    assert "--simulate" in cmd
    assert recording_command.calls[0]["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


def test_download_includes_javascript_runtime(ytdlp, monkeypatch, recording_command):
    monkeypatch.setattr(google, "get_javascript_runtime_args", lambda: ["--js-runtimes", "deno:/d"])
    google.download_video("https://yt.test/a")
    assert recording_command.value_after("--js-runtimes") == "deno:/d"


@pytest.mark.parametrize("requested, sent", [(4, "4"), ("3", "3"), (50, "8")])
def test_download_passes_clamped_concurrent_fragments(ytdlp, no_js_runtime, recording_command, requested, sent):
    google.download_video("https://yt.test/a", concurrent_fragments = requested)
    assert recording_command.value_after("--concurrent-fragments") == sent


@pytest.mark.parametrize("requested", [0, -3, None, "many", 1])
def test_download_runs_single_fragment_for_unusable_concurrency(ytdlp, no_js_runtime, recording_command, requested):
    google.download_video("https://yt.test/a", concurrent_fragments = requested)
    assert "--concurrent-fragments" not in recording_command.only()


@pytest.mark.parametrize("returncode, success", [(0, True), (1, True), (2, False), (-9, False)])
def test_download_result_follows_ytdlp_exit_code(ytdlp, no_js_runtime, monkeypatch, tmp_path, returncode, success):
    FileWritingCommand(monkeypatch, returncode = returncode)
    assert google.download_video("https://yt.test/a", output_dir = str(tmp_path)) is success


def test_download_partial_failure_with_new_files_succeeds(ytdlp, no_js_runtime, monkeypatch, tmp_path):
    FileWritingCommand(monkeypatch, returncode = 1, writes = [tmp_path / "new.mp3"])
    assert google.download_video("https://yt.test/a", output_dir = str(tmp_path)) is True


def test_download_counts_only_files_created_by_this_run(ytdlp, no_js_runtime, monkeypatch, tmp_path):
    (tmp_path / "old.mp3").write_text("")
    FileWritingCommand(monkeypatch, returncode = 1, writes = [tmp_path / "new.mp4", tmp_path / "notes.txt"])
    messages = []
    monkeypatch.setattr(google.logger, "log_info", messages.append)
    google.download_video("https://yt.test/a", output_dir = str(tmp_path))
    assert "Found 1 new media files after download" in messages


def test_download_warns_when_requested_output_dir_is_missing(ytdlp, no_js_runtime, monkeypatch, recording_command, tmp_path):
    warnings = []
    monkeypatch.setattr(google.logger, "log_warning", warnings.append)
    assert google.download_video("https://yt.test/a", output_dir = str(tmp_path / "missing")) is True
    assert any("Output directory" in warning for warning in warnings)


def test_download_without_output_dir_does_not_warn_about_it(ytdlp, no_js_runtime, monkeypatch, recording_command):
    warnings = []
    monkeypatch.setattr(google.logger, "log_warning", warnings.append)
    assert google.download_video("https://yt.test/a") is True
    assert warnings == []


class FakeSanitize:

    def __init__(self, monkeypatch, result = True):
        self.calls = []
        self.result = result
        monkeypatch.setattr(google.fileops, "sanitize_filenames", self)

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.result


def test_download_sanitizes_audio_in_output_dir(ytdlp, no_js_runtime, monkeypatch, recording_command, tmp_path):
    sanitize = FakeSanitize(monkeypatch)
    assert google.download_video("https://yt.test/a", audio_only = True, output_dir = str(tmp_path), sanitize_filenames = True,
        verbose = True, pretend_run = True, exit_on_failure = True) is True
    assert sanitize.calls == [{"path": str(tmp_path), "extension": ".mp3", "verbose": True, "pretend_run": True, "exit_on_failure": True}]


def test_download_sanitizes_directory_of_existing_output_file(ytdlp, no_js_runtime, monkeypatch, recording_command, tmp_path):
    output_file = tmp_path / "video.mp4"
    output_file.write_text("")
    sanitize = FakeSanitize(monkeypatch)
    assert google.download_video("https://yt.test/a", output_file = str(output_file), sanitize_filenames = True) is True
    assert sanitize.calls[0]["path"] == str(tmp_path)
    assert sanitize.calls[0]["extension"] == ".mp4"


def test_download_skips_sanitizing_without_a_directory(ytdlp, no_js_runtime, monkeypatch, recording_command):
    sanitize = FakeSanitize(monkeypatch)
    assert google.download_video("https://yt.test/a", sanitize_filenames = True) is True
    assert sanitize.calls == []


def test_download_fails_when_sanitizing_fails(ytdlp, no_js_runtime, monkeypatch, recording_command, tmp_path):
    FakeSanitize(monkeypatch, result = False)
    assert google.download_video("https://yt.test/a", output_dir = str(tmp_path), sanitize_filenames = True) is False


def test_failed_download_is_not_sanitized(ytdlp, no_js_runtime, monkeypatch, tmp_path):
    FileWritingCommand(monkeypatch, returncode = 2)
    sanitize = FakeSanitize(monkeypatch)
    assert google.download_video("https://yt.test/a", output_dir = str(tmp_path), sanitize_filenames = True) is False
    assert sanitize.calls == []
