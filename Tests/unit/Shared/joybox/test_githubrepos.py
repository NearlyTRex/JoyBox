# Imports
import types

# Local imports
from joybox import githubrepos


###########################################################
# Credentials and selection
#
# Given credentials win over the configured ones; an empty repository list
# selects nothing rather than one empty name.
###########################################################

def test_given_credentials_are_kept(isolated_settings):
    isolated_settings.set_value("UserData.GitHub", "github_username", "configured")

    assert githubrepos.resolve_github_credentials("someone", "token") == ("someone", "token")


def test_missing_credentials_fall_back_to_the_settings(isolated_settings):
    isolated_settings.set_value("UserData.GitHub", "github_username", "configured")
    isolated_settings.set_value("UserData.GitHub", "github_access_token", "configured-token")

    assert githubrepos.resolve_github_credentials() == ("configured", "configured-token")


def test_repository_names_split_on_commas():
    assert githubrepos.split_repository_names("a,b") == ["a", "b"]
    assert githubrepos.split_repository_names("") == []


###########################################################
# Fork updates
###########################################################

def test_only_forks_are_updated(monkeypatch):
    updated = []
    monkeypatch.setattr(githubrepos.network, "update_github_repository", lambda **kwargs: updated.append(kwargs["github_repo"]) or True)
    repositories = [
        types.SimpleNamespace(name = "own", fork = False, default_branch = "main"),
        types.SimpleNamespace(name = "forked", fork = True, default_branch = "main"),
    ]

    githubrepos.update_github_forks(repositories, "someone", "token")

    assert updated == ["forked"]
