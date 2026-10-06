# Imports
import types

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import github_tool


###########################################################
# Repository actions
#
# Archive zips every selected repository; Update only touches forks. A
# repository that fails is warned about and the rest still run.
###########################################################

CONFIGURED_USER = "configured-user"
CONFIGURED_TOKEN = "configured-token-value"
REPOSITORIES = [
    types.SimpleNamespace(name = "own", fork = False, default_branch = "main"),
    types.SimpleNamespace(name = "forked", fork = True, default_branch = "master"),
]


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, github_tool)
    harness.listed = []
    harness.archived = []
    harness.updated = []
    harness.result = True
    isolated_settings.set_value("UserData.GitHub", "github_username", CONFIGURED_USER)
    isolated_settings.set_value("UserData.GitHub", "github_access_token", CONFIGURED_TOKEN)
    network = github_tool.network

    def list_repositories(**kwargs):
        harness.listed.append(kwargs)
        return REPOSITORIES

    def archive(**kwargs):
        harness.archived.append(kwargs)
        return harness.result

    def update(**kwargs):
        harness.updated.append(kwargs)
        return harness.result

    monkeypatch.setattr(network, "get_github_repositories", list_repositories)
    monkeypatch.setattr(network, "archive_github_repository", archive)
    monkeypatch.setattr(network, "update_github_repository", update)
    return harness


def test_archive_zips_every_repository_under_the_user(tool, tmp_path):
    tool.run("--no-preview", "-d", str(tmp_path), "-r", "-c", "-l", "Hetzner")

    assert [call["output_dir"] for call in tool.archived] == [
        str(tmp_path / CONFIGURED_USER / "own"), str(tmp_path / CONFIGURED_USER / "forked")]
    assert all(call["recursive"] and call["clean"] for call in tool.archived)
    assert {call["github_token"] for call in tool.archived} == {CONFIGURED_TOKEN}
    assert tool.archived[0]["locker_type"] == config.LockerType.HETZNER
    assert tool.updated == []


def test_a_missing_archive_dir_stops_before_listing(tool, tmp_path):
    assert tool.exit_code("--no-preview", "-d", str(tmp_path / "absent")) != 0

    assert tool.listed == []


def test_explicit_credentials_and_filters_are_passed_through(tool):
    tool.run("--no-preview", "-a", "Update", "-u", "someone", "-t", "explicit", "-i", "a,b", "-e", "c")

    [call] = tool.listed
    assert (call["github_user"], call["github_token"]) == ("someone", "explicit")
    assert (call["include_repos"], call["exclude_repos"]) == (["a", "b"], ["c"])


def test_update_merges_upstream_into_forks_only(tool):
    tool.run("--no-preview", "-a", "Update")

    assert [(call["github_repo"], call["github_branch"]) for call in tool.updated] == [("forked", "master")]
    assert tool.listed[0]["include_repos"] == tool.listed[0]["exclude_repos"] == []
    assert tool.archived == []


def test_failed_repositories_are_warned_about(tool, tmp_path):
    tool.result = False

    tool.run("--no-preview", "-d", str(tmp_path))
    tool.run("--no-preview", "-a", "Update")

    assert tool.warnings == [
        "Unable to archive repository own", "Unable to archive repository forked", "Unable to update repository forked"]


def test_the_archive_preview_names_the_archive_dir(tool, tmp_path):
    tool.run("-d", str(tmp_path))
    tool.run("-a", "Update")

    archive_details, update_details = (details for _, details in tool.previews)
    assert archive_details[-1] == "Archive dir: %s" % tmp_path
    assert update_details == ["Action: Update", "User: %s" % CONFIGURED_USER, "Repositories: 2"]


def test_a_cancelled_preview_changes_nothing(tool):
    tool.confirm = False

    tool.run("-a", "Update")

    assert tool.updated == []



def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, github_tool)
