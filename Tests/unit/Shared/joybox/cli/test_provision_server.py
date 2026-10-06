# Imports
from typing import ClassVar

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import provision_server


###########################################################
# Input checks and exit status
#
# Every input is checked before anything touches the server; the exit code
# is the failed check count when only verify fails, 1 otherwise.
###########################################################

class FakeServer:

    configured = True

    def __init__(self, index):
        self.index = index

    def is_configured(self):
        return FakeServer.configured


class FakeProvisioner:

    created: ClassVar[list] = []
    result = True
    verify_failures = 0

    def __init__(self, server, components, stages, flags):
        self.server = server
        self.components = components
        self.stages = stages
        self.flags = flags
        self.ran = False
        FakeProvisioner.created.append(self)

    def describe(self):
        return ["plan: %s" % ",".join(self.stages)]

    def run(self):
        self.ran = True
        return FakeProvisioner.result


@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, provision_server)
    harness.missing = []
    harness.selected = []
    harness.paramiko = True
    monkeypatch.setattr(FakeServer, "configured", True)
    monkeypatch.setattr(FakeProvisioner, "created", [])
    monkeypatch.setattr(FakeProvisioner, "result", True)
    monkeypatch.setattr(FakeProvisioner, "verify_failures", 0)
    monkeypatch.setattr(provision_server.serverinfo, "ServerInfo", FakeServer)
    monkeypatch.setattr(provision_server.serverinfo, "select_server", harness.selected.append)
    monkeypatch.setattr(provision_server.provision, "Provisioner", FakeProvisioner)
    monkeypatch.setattr(provision_server.provision, "get_missing_settings", lambda server, stages: harness.missing)
    real_find_spec = provision_server.importlib.util.find_spec
    monkeypatch.setattr(provision_server.importlib.util, "find_spec",
        lambda name, *args: (object() if harness.paramiko else None) if name == "paramiko" else real_find_spec(name, *args))
    return harness


def test_a_successful_run_selects_the_server_and_runs_every_stage(tool):
    tool.run("-s", "1", "-c", "nginx", "certbot")

    [provisioner] = FakeProvisioner.created
    assert provisioner.ran
    assert provisioner.server.index == 1
    assert provisioner.components == ["nginx", "certbot"]
    assert provisioner.stages == provision_server.provision.STAGES
    assert provisioner.flags.pretend_run is False
    assert tool.selected == [1]
    assert "plan: vm,login,day0,deploy,sshd,verify" in tool.infos
    assert tool.infos[-1] == "Server 1 is provisioned"


def test_a_pretend_run_only_describes_the_plan(tool):
    tool.run("-s", "1", "--stages", "deploy", "verify", "-p")

    [provisioner] = FakeProvisioner.created
    assert not provisioner.ran
    assert tool.selected == []
    assert "plan: deploy,verify" in tool.infos


@pytest.mark.parametrize("args, error", [
    (["-s", "1", "stray"], "Unexpected arguments: stray"),
    ([], "--server is required"),
    (["-s", "1", "--stages", "deploy", "reboot"], "Unknown stage(s): reboot"),
])
def test_bad_inputs_stop_before_anything_runs(tool, args, error):
    assert tool.exit_code(*args) != 0
    assert tool.errors == [error]
    assert FakeProvisioner.created == []


def test_an_unconfigured_server_is_refused(tool, monkeypatch):
    monkeypatch.setattr(FakeServer, "configured", False)

    assert tool.exit_code("-s", "3") != 0
    assert tool.errors == ["No host configured for server 3"]


def test_missing_settings_are_named(tool):
    tool.missing = ["server_1_user", "server_1_key"]

    assert tool.exit_code("-s", "1") != 0
    assert tool.errors == ["Set these in ~/JoyBox.ini first: server_1_user, server_1_key"]


def test_a_missing_paramiko_is_refused(tool):
    tool.paramiko = False

    assert tool.exit_code("-s", "1") != 0
    assert tool.errors[0].startswith("paramiko is not installed")
    assert FakeProvisioner.created == []


def test_failed_verify_checks_become_the_exit_code(tool, monkeypatch):
    monkeypatch.setattr(FakeProvisioner, "result", False)
    monkeypatch.setattr(FakeProvisioner, "verify_failures", 3)

    assert tool.exit_code("-s", "1") == 3


def test_verify_failures_from_an_earlier_last_stage_exit_with_one(tool, monkeypatch):
    monkeypatch.setattr(FakeProvisioner, "result", False)
    monkeypatch.setattr(FakeProvisioner, "verify_failures", 3)

    assert tool.exit_code("-s", "1", "--stages", "deploy") == 1


def test_an_earlier_stage_failure_exits_with_one(tool, monkeypatch):
    monkeypatch.setattr(FakeProvisioner, "result", False)

    assert tool.exit_code("-s", "1") == 1


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, provision_server)
