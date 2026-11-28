# Imports
import base64
import sys
import types
import pytest

# Local imports
from joybox import network
from network_helpers import FakeRepo, names

real_github = pytest.importorskip("github")


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

    assert names(network.get_github_repositories("testuser")) == ["GameMetadata", "JoyBox"]


def test_a_repository_owned_by_someone_else_is_skipped(github):
    # get_repos returns collaborations too; archiving those is not the intent.
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("Upstream", owner = "someone-else")]

    assert names(network.get_github_repositories("testuser")) == ["JoyBox"]


def test_no_repositories_list_as_empty(github):
    assert network.get_github_repositories("testuser") == []


def test_the_token_is_passed_through(github):
    github["repos"] = [FakeRepo("JoyBox")]
    network.get_github_repositories("testuser", github_token = "secret")

    assert github["token"] == "secret"


def test_no_token_is_passed_as_none(github):
    network.get_github_repositories("testuser")

    assert github["token"] is None


###########################################################
# Filters
###########################################################

def test_forks_are_excluded_on_request(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("SomeFork", fork = True)]

    assert names(network.get_github_repositories("testuser", exclude_forks = True)) == ["JoyBox"]


def test_forks_are_included_by_default(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("SomeFork", fork = True)]

    assert names(network.get_github_repositories("testuser")) == ["JoyBox", "SomeFork"]


def test_private_repositories_are_excluded_on_request(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("Secrets", private = True)]

    assert names(network.get_github_repositories("testuser", exclude_private = True)) == ["JoyBox"]


def test_private_repositories_are_included_by_default(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("Secrets", private = True)]

    assert names(network.get_github_repositories("testuser")) == ["JoyBox", "Secrets"]


def test_an_include_list_narrows_to_its_members(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata"), FakeRepo("Other")]
    repos = network.get_github_repositories("testuser", include_repos = ["JoyBox", "Other"])

    assert names(repos) == ["JoyBox", "Other"]


def test_an_empty_include_list_includes_everything(github):
    # The default must not mean "include nothing".
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]

    assert names(network.get_github_repositories("testuser", include_repos = [])) == \
        ["GameMetadata", "JoyBox"]


def test_an_exclude_list_removes_its_members(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]
    repos = network.get_github_repositories("testuser", exclude_repos = ["GameMetadata"])

    assert names(repos) == ["JoyBox"]


def test_an_empty_exclude_list_removes_nothing(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]

    assert names(network.get_github_repositories("testuser", exclude_repos = [])) == \
        ["GameMetadata", "JoyBox"]


def test_excluding_wins_over_including(github):
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("GameMetadata")]
    repos = network.get_github_repositories(
        "testuser", include_repos = ["JoyBox", "GameMetadata"], exclude_repos = ["JoyBox"])

    assert names(repos) == ["GameMetadata"]


def test_an_include_list_naming_nothing_present_lists_nothing(github):
    github["repos"] = [FakeRepo("JoyBox")]

    assert network.get_github_repositories("testuser", include_repos = ["Absent"]) == []


def test_repository_names_are_matched_exactly(github):
    # A prefix match would drag in a neighbouring repository.
    github["repos"] = [FakeRepo("JoyBox"), FakeRepo("JoyBoxDocs")]

    assert names(network.get_github_repositories("testuser", include_repos = ["JoyBox"])) == \
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
        "testuser",
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
            raise real_github.GithubException(403, {"message": "rate limited"}, None)

    module = types.ModuleType("github")
    module.Github = Broken
    module.GithubException = real_github.GithubException
    monkeypatch.setitem(sys.modules, "github", module)


def test_an_api_failure_lists_nothing(monkeypatch):
    install_broken_github(monkeypatch)

    assert network.get_github_repositories("testuser") == []


def test_an_api_failure_yields_no_repository(monkeypatch):
    install_broken_github(monkeypatch)

    assert network.get_github_repository("testuser", "JoyBox") is None


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
    repo = network.get_github_repository("testuser", "JoyBox")

    assert seen == ["testuser/JoyBox"]
    assert repo.name == "JoyBox"


def test_a_failed_repository_lookup_can_quit_the_program(monkeypatch):
    install_broken_github(monkeypatch)

    with pytest.raises(SystemExit):
        network.get_github_repository("testuser", "JoyBox", exit_on_failure = True)


def test_a_failed_repository_listing_can_quit_the_program(monkeypatch):
    install_broken_github(monkeypatch)

    with pytest.raises(SystemExit):
        network.get_github_repositories("testuser", exit_on_failure = True)


def test_verbose_github_calls_name_what_they_fetch(github, monkeypatch):
    logged = []
    monkeypatch.setattr(network.logger, "log_info", logged.append)

    network.get_github_repositories("testuser", verbose = True)
    network.get_github_repository("testuser", "JoyBox", verbose = True)

    assert any("'testuser'" in line for line in logged)
    assert any("'testuser/JoyBox'" in line for line in logged)


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


def test_a_public_repository_clone_sets_no_credentials(cloned):
    network.download_github_repository("NearlyTRex", "Nile", output_dir = "/out")

    assert cloned[0]["env_vars"] is None


def test_a_token_authenticates_the_clone_through_its_environment(cloned):
    network.download_github_repository("NearlyTRex", "Nile", github_token = GITHUB_TOKEN, output_dir = "/out")

    assert cloned[0]["url"] == "https://github.com/NearlyTRex/Nile.git"
    assert cloned[0]["env_vars"] == network.get_github_auth_env(GITHUB_TOKEN)


@pytest.mark.parametrize("token", ["", None, 12345])
def test_a_token_that_is_not_text_is_left_out(cloned, token):
    network.download_github_repository("NearlyTRex", "Nile", github_token = token, output_dir = "/out")

    assert cloned[0]["url"] == "https://github.com/NearlyTRex/Nile.git"
    assert cloned[0]["env_vars"] is None


def test_the_auth_environment_sends_the_token_only_to_github():
    env_vars = network.get_github_auth_env(GITHUB_TOKEN)

    assert env_vars["GIT_CONFIG_COUNT"] == "1"
    assert env_vars["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    scheme, encoded = env_vars["GIT_CONFIG_VALUE_0"].removeprefix("Authorization: ").split(" ")
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == "x-access-token:%s" % GITHUB_TOKEN


def test_a_token_never_reaches_the_clone_command_line(installed, recording_command, tmp_path):
    # Argv is visible to every user through ps, and the clone url is saved as
    # the remote in .git/config, so the token may sit in neither.
    network.download_github_repository("NearlyTRex", "Nile", github_token = GITHUB_TOKEN, output_dir = str(tmp_path / "repo"))

    cmd = recording_command.only()
    assert not any(GITHUB_TOKEN in arg for arg in cmd)
    assert cmd[-2] == "https://github.com/NearlyTRex/Nile.git"
    header = recording_command.options().get_env_var("GIT_CONFIG_VALUE_0")
    assert base64.b64encode(("x-access-token:%s" % GITHUB_TOKEN).encode()).decode() in header


def test_a_public_clone_runs_with_the_inherited_environment(installed, recording_command, monkeypatch, tmp_path):
    monkeypatch.delenv("GIT_CONFIG_KEY_0", raising = False)

    network.download_github_repository("NearlyTRex", "Nile", output_dir = str(tmp_path / "repo"))

    assert recording_command.options().get_env_var("GIT_CONFIG_KEY_0") is None


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

    network.update_github_repository("NearlyTRex", "Nile", "dev", github_token = GITHUB_TOKEN)

    assert any(expected in line for line in logged)


def test_a_merge_without_a_message_still_succeeds(merge):
    merge["response"] = {"merge_type": "none"}

    assert network.update_github_repository("NearlyTRex", "Nile", "dev", github_token = GITHUB_TOKEN) is True


def test_a_refused_merge_fails(merge):
    merge["response"] = None

    assert network.update_github_repository("NearlyTRex", "Nile", "dev", github_token = GITHUB_TOKEN) is False


def test_a_pretend_update_merges_nothing(merge):
    assert network.update_github_repository("NearlyTRex", "Nile", "dev", github_token = GITHUB_TOKEN, pretend_run = True) is True
    assert merge["calls"] == []


def test_a_merge_without_a_token_is_refused_before_any_request(merge, monkeypatch):
    errors = []
    monkeypatch.setattr(network.logger, "log_error", errors.append)

    assert network.update_github_repository("NearlyTRex", "Nile", "dev") is False
    assert merge["calls"] == []
    assert errors == ["Updating repository 'NearlyTRex' - 'Nile' from upstream needs a GitHub token"]


def test_api_headers_carry_the_token_and_pin_the_api_version():
    headers = network.get_github_api_headers(GITHUB_TOKEN)

    assert headers["Authorization"] == "Bearer %s" % GITHUB_TOKEN
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
