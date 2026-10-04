# Imports
import sys
import types
import pytest

# Local imports
from joybox import network
from network_helpers import FakeRepo, names


GITHUB_TOKEN = "ghp_exampletoken"


###########################################################
# Github repository listing
#
# Drives which repositories get archived. A repository wrongly included is
# extra work; one wrongly excluded is silently never backed up.
###########################################################

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

def install_broken_github(monkeypatch):
    class Broken:
        def __init__(self, token = None):
            raise RuntimeError("rate limited")

    module = types.ModuleType("github")
    module.Github = Broken
    monkeypatch.setitem(sys.modules, "github", module)


def test_an_api_failure_lists_nothing(monkeypatch):
    install_broken_github(monkeypatch)

    assert network.get_github_repositories("aryie") == []


def test_an_api_failure_yields_no_repository(monkeypatch):
    install_broken_github(monkeypatch)

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


def test_a_failed_repository_lookup_can_quit_the_program(monkeypatch):
    install_broken_github(monkeypatch)

    with pytest.raises(SystemExit):
        network.get_github_repository("aryie", "JoyBox", exit_on_failure = True)


def test_a_failed_repository_listing_can_quit_the_program(monkeypatch):
    install_broken_github(monkeypatch)

    with pytest.raises(SystemExit):
        network.get_github_repositories("aryie", exit_on_failure = True)


def test_verbose_github_calls_name_what_they_fetch(github, monkeypatch):
    logged = []
    monkeypatch.setattr(network.logger, "log_info", logged.append)

    network.get_github_repositories("aryie", verbose = True)
    network.get_github_repository("aryie", "JoyBox", verbose = True)

    assert any("'aryie'" in line for line in logged)
    assert any("'aryie/JoyBox'" in line for line in logged)


###########################################################
# Cloning
###########################################################

@pytest.fixture
def cloned(monkeypatch):
    seen = []
    monkeypatch.setattr(network, "download_git_url", lambda **kwargs: seen.append(kwargs) or True)
    return seen


def test_a_public_repository_is_cloned_anonymously(cloned):
    network.download_github_repository("NearlyTRex", "Nile", output_dir = "/out")

    assert cloned[0]["url"] == "https://github.com/NearlyTRex/Nile.git"


def test_a_token_authenticates_the_clone(cloned):
    network.download_github_repository("NearlyTRex", "Nile", github_token = GITHUB_TOKEN, output_dir = "/out")

    assert cloned[0]["url"] == "https://%s@github.com/NearlyTRex/Nile.git" % GITHUB_TOKEN


@pytest.mark.parametrize("token", ["", None, 12345])
def test_a_token_that_is_not_text_is_left_out(cloned, token):
    network.download_github_repository("NearlyTRex", "Nile", github_token = token, output_dir = "/out")

    assert cloned[0]["url"] == "https://github.com/NearlyTRex/Nile.git"


###########################################################
# Updating forks
###########################################################

@pytest.fixture
def merge(monkeypatch):
    state = {"response": {"message": "Successfully fetched and fast-forwarded from upstream"}, "calls": []}

    def post(**kwargs):
        state["calls"].append(kwargs)
        return state["response"]

    monkeypatch.setattr(network, "post_remote_json", post)
    return state


def test_a_fork_is_merged_from_upstream_on_its_branch(merge):
    assert network.update_github_repository("NearlyTRex", "Nile", "dev", github_token = GITHUB_TOKEN) is True

    call = merge["calls"][0]
    assert call["url"] == "https://api.github.com/repos/NearlyTRex/Nile/merge-upstream"
    assert call["data"] == {"branch": "dev"}
    assert call["headers"]["Authorization"] == "Bearer %s" % GITHUB_TOKEN


@pytest.mark.parametrize("message, expected", [
    ("Successfully fetched and fast-forwarded from upstream", "successfully updated"),
    ("This branch is not behind the upstream", "already up to date"),
])
def test_the_merge_outcome_is_reported(merge, monkeypatch, message, expected):
    logged = []
    monkeypatch.setattr(network.logger, "log_info", logged.append)
    merge["response"] = {"message": message}

    network.update_github_repository("NearlyTRex", "Nile", "dev")

    assert any(expected in line for line in logged)


def test_a_merge_without_a_message_still_succeeds(merge):
    merge["response"] = {"merge_type": "none"}

    assert network.update_github_repository("NearlyTRex", "Nile", "dev") is True


def test_a_refused_merge_fails(merge):
    merge["response"] = None

    assert network.update_github_repository("NearlyTRex", "Nile", "dev") is False


def test_a_pretend_update_merges_nothing(merge):
    assert network.update_github_repository("NearlyTRex", "Nile", "dev", pretend_run = True) is True
    assert merge["calls"] == []
