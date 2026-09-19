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
