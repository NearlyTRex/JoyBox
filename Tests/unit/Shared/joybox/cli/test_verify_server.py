# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import hardening
from joybox.cli import verify_server


###########################################################
# Gate
#
# The exit status is the number of failed checks, and the connection is torn
# down even when a check raises.
###########################################################

class FakeConnection:

    def __init__(self):
        self.events = []

    def setup(self):
        self.events.append("setup")

    def teardown(self):
        self.events.append("teardown")


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, verify_server)
    harness.connection = FakeConnection()
    harness.results = []
    harness.checked = []
    harness.connected = []

    def get_connection(server_index, flags):
        harness.connected.append((server_index, flags))
        return harness.connection

    def verify(**kwargs):
        harness.checked.append(kwargs)
        if isinstance(harness.results, Exception):
            raise harness.results
        return harness.results

    monkeypatch.setattr(verify_server.serverinfo, "get_connection", get_connection)
    monkeypatch.setattr(verify_server.runner, "get_public_ports", lambda server: [80, 443])
    monkeypatch.setattr(verify_server.hardening, "verify_hardening", verify)
    return harness


def test_a_clean_server_exits_zero(tool, capsys):
    tool.results = [hardening.CheckResult("Firewall", hardening.PASS, "ufw active")]

    with pytest.raises(SystemExit) as raised:
        tool.run("-s", "0", "-d", "joybox.test", "-v")

    assert raised.value.code == 0
    assert "All checks passed." in capsys.readouterr().out
    assert tool.connection.events == ["setup", "teardown"]
    [call] = tool.checked
    assert (call["domain"], call["public_ports"]) == ("joybox.test", [80, 443])
    [(server, flags)] = tool.connected
    assert server == "0" and flags.verbose


def test_the_exit_status_counts_the_failures(tool, capsys):
    tool.results = [
        hardening.CheckResult("Firewall", hardening.FAIL, "ufw inactive", ["state: off"]),
        hardening.CheckResult("SSH", hardening.FAIL, "password login allowed"),
        hardening.CheckResult("SSH", hardening.SKIP, "no keys"),
    ]

    with pytest.raises(SystemExit) as raised:
        tool.run()

    assert raised.value.code == 2
    output = capsys.readouterr().out
    assert "2 check(s) failed." in output
    assert "state: off" in output


def test_the_connection_is_torn_down_when_a_check_raises(tool):
    tool.results = RuntimeError("boom")

    assert tool.exit_code() != 0

    assert tool.connection.events == ["setup", "teardown"]


def test_an_unconfigured_server_is_refused(tool):
    tool.connection = None

    assert tool.exit_code("-s", "3") != 0

    assert tool.errors == ["No host configured for server 3"]
    assert tool.checked == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, verify_server)
