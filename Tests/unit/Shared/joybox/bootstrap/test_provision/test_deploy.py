# Imports
import pytest

# Local imports
from joybox.bootstrap import provision
from provision_helpers import SECTION, World, build


###########################################################
# Deploy
###########################################################

class FakeEnvironment:
    def __init__(self, result = True):
        self.result = result
        self.components = None
        self.events = []

    def set_components_to_process(self, components):
        self.components = components

    def setup(self):
        self.events.append("setup")
        return self.result

    def disconnect(self):
        self.events.append("disconnect")


@pytest.fixture
def deploy_env(entry, monkeypatch):
    environment = FakeEnvironment()
    requests = []
    monkeypatch.setattr(provision.runner, "create_environment",
                        lambda **kwargs: requests.append(kwargs) or environment)
    environment.requests = requests
    return environment


def test_deploy_sets_up_the_remote_environment(deploy_env):
    assert build(World({})).run_deploy() is True
    assert deploy_env.requests[0]["environment_type"] == provision.constants.EnvironmentType.REMOTE_UBUNTU
    assert deploy_env.requests[0]["server_index"] == 1
    assert deploy_env.components is None
    assert deploy_env.events == ["setup", "disconnect"]


def test_deploy_limits_itself_to_the_chosen_components(deploy_env):
    provisioner = build(World({}))
    provisioner.components = ["nginx"]

    assert provisioner.run_deploy() is True
    assert deploy_env.components == ["nginx"]


def test_a_failed_deploy_still_disconnects(deploy_env):
    deploy_env.result = False

    assert build(World({})).run_deploy() is False
    assert deploy_env.events == ["setup", "disconnect"]


def test_deploy_without_an_environment_fails(entry, monkeypatch):
    monkeypatch.setattr(provision.runner, "create_environment", lambda **kwargs: None)

    assert build(World({})).run_deploy() is False


@pytest.fixture
def mkcert_entry(deploy_env, entry, monkeypatch):
    entry.set_value(SECTION, "server_1_tls_mode", "mkcert")
    monkeypatch.setattr(provision, "is_mkcert_ready", lambda: False)
    return deploy_env


def test_mkcert_not_installed_stops_the_deploy(mkcert_entry, monkeypatch):
    monkeypatch.setattr(provision.command, "is_runnable_command", lambda cmd: False)

    assert build(World({})).run_deploy() is False
    assert mkcert_entry.events == []


def test_mkcert_is_trusted_before_deploying(mkcert_entry, monkeypatch):
    ran = []
    monkeypatch.setattr(provision.command, "is_runnable_command", lambda cmd: True)
    monkeypatch.setattr(provision.command, "run_interactive_command", lambda cmd: ran.append(cmd) or 0)

    assert build(World({})).run_deploy() is True
    assert ran == [["mkcert", "-install"]]
    assert mkcert_entry.events == ["setup", "disconnect"]


def test_mkcert_that_cannot_be_trusted_stops_the_deploy(mkcert_entry, monkeypatch):
    monkeypatch.setattr(provision.command, "is_runnable_command", lambda cmd: True)
    monkeypatch.setattr(provision.command, "run_interactive_command", lambda cmd: 1)

    assert build(World({})).run_deploy() is False
    assert mkcert_entry.events == []
