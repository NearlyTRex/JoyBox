# Imports
import types


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


def names(repos):
    return sorted(repo.name for repo in repos)


class FakeResponse:

    def __init__(self, status_code = 200, payload = None, text = ""):
        self.status_code = status_code
        self.payload = payload
        self.text = text

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


def only_call(state):
    assert len(state["calls"]) == 1, "expected one request, recorded %d" % len(state["calls"])
    return state["calls"][0]


TOOL_PATHS = {
    "Curl": "/tools/curl",
    "Git": "/tools/git",
}
