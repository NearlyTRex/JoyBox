# Imports
import sys
import types
import pytest

# Local imports
from joybox import network


###########################################################
# Github repository listing
#
# Drives which repositories get archived. A repository wrongly included is
# extra work; one wrongly excluded is silently never backed up.
###########################################################

class FakeRepo:

    def __init__(self, name, owner = "aryie", fork = False, private = False):
        self.name = name
        self.owner = types.SimpleNamespace(login = owner)
        self.fork = fork
        self.private = private


class FakeUser:

    def __init__(self, login, repos):
        self.login = login
        self.repos = repos

    def get_repos(self, visibility = None):
        return self.repos


@pytest.fixture
def github(monkeypatch):
    state = {"repos": [], "login": "aryie", "token": None}

    class FakeGithub:
        def __init__(self, token = None):
            state["token"] = token

        def get_user(self):
            return FakeUser(state["login"], state["repos"])

    module = types.ModuleType("github")
    module.Github = FakeGithub
    monkeypatch.setitem(sys.modules, "github", module)
    return state


def names(repos):
    return sorted(repo.name for repo in repos)


###########################################################
# Ownership
###########################################################

def test_every_owned_repository_is_listed(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]

    assert names(network.get_github_repositories("aryie")) == ["GameMetadata", "JoyBox"]


def test_a_repository_owned_by_someone_else_is_skipped(github):
    # get_repos returns collaborations too; archiving those is not the intent.
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("Upstream", owner = "someone-else")]

    assert names(network.get_github_repositories("aryie")) == ["JoyBox"]


def test_no_repositories_list_as_empty(github):
    assert network.get_github_repositories("aryie") == []


def test_the_token_is_passed_through(github):
    github["repos"] = [FakeRepo("JoyBox")]
    network.get_github_repositories("aryie", github_token = "secret")

    assert github["token"] == "secret"


def test_no_token_is_passed_as_none(github):
    network.get_github_repositories("aryie")

    assert github["token"] is None


###########################################################
# Filters
###########################################################

def test_forks_are_excluded_on_request(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("SomeFork", fork = True)]

    assert names(network.get_github_repositories("aryie", exclude_forks = True)) == ["JoyBox"]


def test_forks_are_included_by_default(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("SomeFork", fork = True)]

    assert names(network.get_github_repositories("aryie")) == ["JoyBox", "SomeFork"]


def test_private_repositories_are_excluded_on_request(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("Secrets", private = True)]

    assert names(network.get_github_repositories("aryie", exclude_private = True)) == ["JoyBox"]


def test_private_repositories_are_included_by_default(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("Secrets", private = True)]

    assert names(network.get_github_repositories("aryie")) == ["JoyBox", "Secrets"]


def test_an_include_list_narrows_to_its_members(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata"), FakeRepo("Other")]
    repos = network.get_github_repositories("aryie", include_repos = ["JoyBox", "Other"])

    assert names(repos) == ["JoyBox", "Other"]


def test_an_empty_include_list_includes_everything(github):
    # The default must not mean "include nothing".
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]

    assert names(network.get_github_repositories("aryie", include_repos = [])) == \
        ["GameMetadata", "JoyBox"]


def test_an_exclude_list_removes_its_members(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]
    repos = network.get_github_repositories("aryie", exclude_repos = ["GameMetadata"])

    assert names(repos) == ["JoyBox"]


def test_an_empty_exclude_list_removes_nothing(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]

    assert names(network.get_github_repositories("aryie", exclude_repos = [])) == \
        ["GameMetadata", "JoyBox"]


def test_excluding_wins_over_including(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]
    repos = network.get_github_repositories(
        "aryie", include_repos = ["JoyBox", "GameMetadata"], exclude_repos = ["JoyBox"])

    assert names(repos) == ["GameMetadata"]


def test_an_include_list_naming_nothing_present_lists_nothing(github):
    github["repos"] = [FakeRepo("JoyBox")]

    assert network.get_github_repositories("aryie", include_repos = ["Absent"]) == []


def test_repository_names_are_matched_exactly(github):
    # A prefix match would drag in a neighbouring repository.
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("JoyBoxDocs")]

    assert names(network.get_github_repositories("aryie", include_repos = ["JoyBox"])) == \
        ["JoyBox"]


def test_every_filter_applies_together(github):
    github["repos"] = [
        FakeRepo("JoyBox"),
        FakeRepo("GameMetadata"),
        FakeRepo("SomeFork", fork = True),
        FakeRepo("Secrets", private = True),
        FakeRepo("Upstream", owner = "someone-else"),
    ]
    repos = network.get_github_repositories(
        "aryie",
        include_repos = ["JoyBox", "GameMetadata", "SomeFork", "Secrets", "Upstream"],
        exclude_repos = ["GameMetadata"],
        exclude_forks = True,
        exclude_private = True)

    assert names(repos) == ["JoyBox"]


###########################################################
# Failures
###########################################################

def test_an_api_failure_lists_nothing(monkeypatch):
    class Broken:
        def __init__(self, token = None):
            raise RuntimeError("rate limited")

    module = types.ModuleType("github")
    module.Github = Broken
    monkeypatch.setitem(sys.modules, "github", module)

    assert network.get_github_repositories("aryie") == []


def test_an_api_failure_yields_no_repository(monkeypatch):
    class Broken:
        def __init__(self, token = None):
            raise RuntimeError("rate limited")

    module = types.ModuleType("github")
    module.Github = Broken
    monkeypatch.setitem(sys.modules, "github", module)

    assert network.get_github_repository("aryie", "JoyBox") is None


###########################################################
# Single repository
###########################################################

def test_a_repository_is_fetched_by_its_full_name(monkeypatch):
    seen = []

    class FakeGithub:
        def __init__(self, token = None):
            pass

        def get_repo(self, full_name):
            seen.append(full_name)
            return FakeRepo("JoyBox")

    module = types.ModuleType("github")
    module.Github = FakeGithub
    monkeypatch.setitem(sys.modules, "github", module)
    repo = network.get_github_repository("aryie", "JoyBox")

    assert seen == ["aryie/JoyBox"]
    assert repo.name == "JoyBox"


###########################################################
# Remote requests
#
# Every request goes out through requests, and every one of these returns
# nothing rather than raising when the far end misbehaves - callers treat a
# None as "not available" and carry on.
###########################################################

class FakeResponse:

    def __init__(self, status_code = 200, payload = None, text = ""):
        self.status_code = status_code
        self.payload = payload
        self.text = text

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


@pytest.fixture
def requests_module(monkeypatch):
    # A stand-in for requests, so the behaviour of each wrapper can be driven
    # without reaching the network.
    state = {"response": FakeResponse(), "error": None, "calls": []}

    def record(method):
        def run(url, headers = None, timeout = None, json = None):
            state["calls"].append({
                "method": method,
                "url": url,
                "headers": headers,
                "timeout": timeout,
                "json": json,
            })
            if state["error"]:
                raise state["error"]
            return state["response"]
        return run

    module = types.ModuleType("requests")
    module.get = record("get")
    module.post = record("post")
    monkeypatch.setitem(sys.modules, "requests", module)
    return state


def only_call(state):
    assert len(state["calls"]) == 1, "expected one request, recorded %d" % len(state["calls"])
    return state["calls"][0]


###########################################################
# Reachability
###########################################################

def test_a_serving_url_is_reachable(requests_module):
    assert network.is_url_reachable("https://example.test") is True


@pytest.mark.parametrize("status_code", [301, 404, 500])
def test_a_url_that_does_not_answer_with_success_is_unreachable(requests_module, status_code):
    requests_module["response"] = FakeResponse(status_code = status_code)

    assert network.is_url_reachable("https://example.test") is False


def test_a_refused_connection_is_unreachable(requests_module):
    requests_module["error"] = OSError("connection refused")

    assert network.is_url_reachable("https://example.test") is False


###########################################################
# JSON
###########################################################

def test_json_is_returned_from_a_successful_response(requests_module):
    requests_module["response"] = FakeResponse(payload = {"models": []})

    assert network.get_remote_json("https://example.test/api") == {"models": []}


def test_a_json_request_asks_for_json(requests_module):
    network.get_remote_json("https://example.test/api")

    assert only_call(requests_module)["headers"] == {"Accept": "application/json"}


def test_a_json_request_can_carry_its_own_headers(requests_module):
    network.get_remote_json("https://example.test/api", headers = {"HX-Request": "true"})

    assert only_call(requests_module)["headers"] == {"HX-Request": "true"}


@pytest.mark.parametrize("status_code", [404, 500])
def test_an_unsuccessful_json_response_yields_nothing(requests_module, status_code):
    requests_module["response"] = FakeResponse(status_code = status_code, payload = {"error": "nope"})

    assert network.get_remote_json("https://example.test/api") is None


def test_an_unreachable_json_endpoint_yields_nothing(requests_module):
    requests_module["error"] = OSError("no route to host")

    assert network.get_remote_json("https://example.test/api") is None


def test_a_response_that_is_not_json_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(payload = ValueError("not json"))

    assert network.get_remote_json("https://example.test/api") is None


def test_a_failed_json_request_can_quit_the_program(requests_module):
    requests_module["error"] = OSError("no route to host")

    with pytest.raises(SystemExit):
        network.get_remote_json("https://example.test/api", exit_on_failure = True)


def test_json_is_posted_as_the_request_body(requests_module):
    requests_module["response"] = FakeResponse(payload = {"ok": True})

    result = network.post_remote_json("https://example.test/api", data = {"prompt": "hello"})

    assert result == {"ok": True}
    assert only_call(requests_module)["json"] == {"prompt": "hello"}


def test_a_post_uses_the_post_method(requests_module):
    network.post_remote_json("https://example.test/api", data = {})

    assert only_call(requests_module)["method"] == "post"


def test_an_unsuccessful_post_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(status_code = 401, payload = {"error": "denied"})

    assert network.post_remote_json("https://example.test/api", data = {}) is None


def test_a_failed_post_can_quit_the_program(requests_module):
    requests_module["error"] = OSError("no route to host")

    with pytest.raises(SystemExit):
        network.post_remote_json("https://example.test/api", exit_on_failure = True)


###########################################################
# HTML
###########################################################

def test_html_is_returned_as_text(requests_module):
    requests_module["response"] = FakeResponse(text = "<html></html>")

    assert network.get_remote_html("https://example.test") == "<html></html>"


def test_an_html_request_does_not_wait_forever(requests_module):
    # A scrape that hangs holds up the whole run with no way to interrupt it.
    network.get_remote_html("https://example.test")

    assert only_call(requests_module)["timeout"] == 10


def test_an_html_request_sends_no_headers_of_its_own(requests_module):
    network.get_remote_html("https://example.test")

    assert only_call(requests_module)["headers"] == {}


def test_an_unsuccessful_html_response_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(status_code = 404, text = "not found")

    assert network.get_remote_html("https://example.test") is None


def test_an_unreachable_page_yields_nothing(requests_module):
    requests_module["error"] = OSError("no route to host")

    assert network.get_remote_html("https://example.test") is None


###########################################################
# XML
###########################################################

def test_xml_is_parsed_into_a_mapping(requests_module):
    requests_module["response"] = FakeResponse(text = "<root><name>value</name></root>")

    assert network.get_remote_xml("https://example.test/feed") == {"root": {"name": "value"}}


def test_an_xml_request_asks_for_xml(requests_module):
    requests_module["response"] = FakeResponse(text = "<root/>")

    network.get_remote_xml("https://example.test/feed")

    assert only_call(requests_module)["headers"] == {"Accept": "text/xml"}


def test_malformed_xml_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(text = "<root><unclosed>")

    assert network.get_remote_xml("https://example.test/feed") is None


def test_an_unsuccessful_xml_response_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(status_code = 500, text = "<root/>")

    assert network.get_remote_xml("https://example.test/feed") is None


###########################################################
# Downloading
###########################################################

TOOL_PATHS = {
    "Curl": "/tools/curl",
    "Git": "/tools/git",
}


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(network.programs, "is_tool_installed", lambda name: name in TOOL_PATHS)
    monkeypatch.setattr(network.programs, "get_tool_program", lambda name: TOOL_PATHS.get(name))
    return TOOL_PATHS


@pytest.fixture
def missing(monkeypatch):
    monkeypatch.setattr(network.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(network.programs, "get_tool_program", lambda name: None)


def test_a_download_follows_redirects(installed, recording_command, tmp_path):
    # Nearly every release link is a redirect to a CDN, and without -L the
    # downloaded file is the redirect page.
    target = tmp_path / "file.bin"
    target.write_text("payload")

    network.download_url("https://example.test/file.bin", output_file = str(target))

    assert "-L" in recording_command.only()


def test_a_download_to_a_file_names_the_output(installed, recording_command, tmp_path):
    target = tmp_path / "file.bin"
    target.write_text("payload")

    assert network.download_url("https://example.test/file.bin", output_file = str(target)) is True
    assert recording_command.value_after("--output") == str(target)


def test_a_download_to_a_directory_keeps_the_remote_name(installed, recording_command, tmp_path):
    target = tmp_path / "downloads"
    target.mkdir()
    (target / "file.bin").write_text("payload")

    assert network.download_url("https://example.test/file.bin", output_dir = str(target)) is True
    assert recording_command.value_after("--output-dir") == str(target)
    assert "-O" in recording_command.only()


def test_a_download_that_wrote_nothing_reports_failure(installed, recording_command, tmp_path):
    # Curl can return zero and leave no file, and the caller would then read a
    # path that is not there.
    assert network.download_url(
        "https://example.test/file.bin",
        output_file = str(tmp_path / "absent.bin")) is False


def test_a_download_to_a_directory_without_the_file_reports_failure(installed, recording_command, tmp_path):
    target = tmp_path / "downloads"
    target.mkdir()

    assert network.download_url("https://example.test/file.bin", output_dir = str(target)) is False


def test_a_download_with_no_destination_reports_failure(installed, recording_command):
    assert network.download_url("https://example.test/file.bin") is False


def test_a_failed_download_reports_failure(installed, monkeypatch, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)
    target = tmp_path / "file.bin"
    target.write_text("payload")

    assert network.download_url("https://example.test/file.bin", output_file = str(target)) is False


def test_downloading_without_curl_reports_failure(missing, recording_command):
    assert network.download_url("https://example.test/file.bin", output_file = "/tmp/file.bin") is False
    assert recording_command.ran() is False


###########################################################
# Cloning
###########################################################

def test_a_clone_brings_its_submodules(installed, recording_command, tmp_path):
    # A repository cloned without submodules is missing the tools it vendors.
    target = tmp_path / "repo"
    target.mkdir()

    network.download_git_url("https://example.test/repo.git", str(target))

    assert "--recursive" in recording_command.only()


def test_a_clone_can_leave_submodules_out(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    network.download_git_url("https://example.test/repo.git", str(target), recursive = False)

    assert "--recursive" not in recording_command.only()


def test_a_clone_can_name_a_branch(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    network.download_git_url("https://example.test/repo.git", str(target), branch = "stable")

    assert recording_command.value_after("--branch") == "stable"


def test_a_clone_names_the_url_and_destination_last(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    network.download_git_url("https://example.test/repo.git", str(target))

    assert recording_command.only()[-2:] == ["https://example.test/repo.git", str(target)]


def test_a_populated_destination_is_not_cloned_over(installed, recording_command, tmp_path):
    # Cloning into a checkout that already has work in it would fail anyway,
    # and the caller only wants the repository present.
    target = tmp_path / "repo"
    target.mkdir()
    (target / "README.md").write_text("already here")

    assert network.download_git_url("https://example.test/repo.git", str(target)) is True
    assert recording_command.ran() is False


def test_a_clean_clone_empties_the_destination_first(installed, recording_command, monkeypatch, tmp_path):
    emptied = []
    monkeypatch.setattr(
        network.fileops, "remove_directory_contents",
        lambda src, **kwargs: emptied.append(src) or True)
    monkeypatch.setattr(network.fileops, "chmod_file_or_directory", lambda **kwargs: True)
    target = tmp_path / "repo"
    target.mkdir()
    (target / "README.md").write_text("stale")

    network.download_git_url("https://example.test/repo.git", str(target), clean = True)

    assert emptied == [str(target)]


def test_a_first_clean_clone_has_nothing_to_clear(installed, recording_command, monkeypatch, tmp_path):
    # The destination does not exist yet on a first clone, and clearing it
    # would ask for permissions on a path that is not there.
    def fail(**kwargs):
        raise AssertionError("there is nothing to clear before a first clone")

    monkeypatch.setattr(network.fileops, "chmod_file_or_directory", fail)
    monkeypatch.setattr(network.fileops, "remove_directory_contents", fail)

    network.download_git_url(
        "https://example.test/repo.git", str(tmp_path / "absent"), clean = True)

    assert recording_command.ran() is True


def test_a_clone_that_produced_nothing_reports_failure(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    assert network.download_git_url("https://example.test/repo.git", str(target)) is False


def test_a_failed_clone_reports_failure(installed, monkeypatch, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)
    target = tmp_path / "repo"
    target.mkdir()

    assert network.download_git_url("https://example.test/repo.git", str(target)) is False


def test_cloning_without_git_reports_failure(missing, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    assert network.download_git_url("https://example.test/repo.git", str(target)) is False
    assert recording_command.ran() is False


###########################################################
# Network shares
###########################################################

def test_a_mounted_share_is_recognised(monkeypatch):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(
        network.command, "run_output_command",
        lambda cmd: "//server/share on /mnt/share type cifs (rw)")

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is True


def test_a_share_mounted_somewhere_else_is_not_recognised(monkeypatch):
    # Two mounts of the same share is how a backup ends up written to the
    # wrong directory.
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(
        network.command, "run_output_command",
        lambda cmd: "//server/share on /mnt/other type cifs (rw)")

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is False


def test_an_unmounted_share_is_not_recognised(monkeypatch):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: False)
    monkeypatch.setattr(network.platform_info, "is_linux_platform", lambda: True)
    monkeypatch.setattr(network.command, "run_output_command", lambda cmd: "")

    assert network.is_network_share_mounted("/mnt/share", "server", "share") is False


def test_a_windows_share_is_recognised_by_its_contents(monkeypatch, tmp_path):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: True)
    (tmp_path / "file.txt").write_text("data")

    assert network.is_network_share_mounted(str(tmp_path), "server", "share") is True


def test_an_empty_windows_mount_point_is_not_a_share(monkeypatch, tmp_path):
    monkeypatch.setattr(network.platform_info, "is_windows_platform", lambda: True)

    assert network.is_network_share_mounted(str(tmp_path), "server", "share") is False
