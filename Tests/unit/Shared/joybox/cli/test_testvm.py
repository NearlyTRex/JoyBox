# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import testvm


###########################################################
# testvm
#
# Each action dispatches to one virtualmachine call; libvirt, the console and
# /etc/hosts are all replaced, so nothing reaches the host.
###########################################################

NAME = testvm.virtualmachine.DEFAULT_NAME


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, testvm)
    vm = testvm.virtualmachine
    command.create = Recorder(result = True)
    command.destroy = Recorder(result = True)
    command.snapshot = Recorder(result = True)
    command.revert = Recorder(result = True)
    command.ip = Recorder(result = "192.168.122.10")
    command.console = Recorder(result = 0)
    command.set_hosts = Recorder(result = True)
    command.remove_hosts = Recorder(result = True)
    monkeypatch.setattr(vm, "create_vm", command.create)
    monkeypatch.setattr(vm, "destroy_vm", command.destroy)
    monkeypatch.setattr(vm, "snapshot_vm", command.snapshot)
    monkeypatch.setattr(vm, "revert_vm", command.revert)
    monkeypatch.setattr(vm, "list_snapshots", lambda name, verbose: ["clean", "after-tls"])
    monkeypatch.setattr(vm, "get_vm_ip", command.ip)
    monkeypatch.setattr(vm, "get_console_command", lambda name: ["virsh", "console", name])
    monkeypatch.setattr(testvm.command, "run_interactive_command", command.console)
    monkeypatch.setattr(testvm.hostsfile, "set_entries", command.set_hosts)
    monkeypatch.setattr(testvm.hostsfile, "remove_entries", command.remove_hosts)
    return command


def test_create_passes_the_machine_shape(tool):
    tool.main("create", "-n", "guest", "-k", "key.pub", "-a", "10.0.0.5", "--release", "jammy",
        "--memory", "2048", "--vcpus", "4", "--disk_size", "40", "-p")

    assert tool.create.calls == [{
        "vm_name": "guest",
        "ssh_key_file": "key.pub",
        "address": "10.0.0.5",
        "memory": 2048,
        "vcpus": 4,
        "disk_size": 40,
        "release": "jammy",
        "verbose": False,
        "pretend_run": True,
        "exit_on_failure": False}]
    assert tool.infos == ["Booting at 10.0.0.5; first boot takes a minute or two"]


def test_create_defaults_come_from_virtualmachine(tool):
    tool.main("create")

    call = tool.create.calls[0]
    vm = testvm.virtualmachine
    assert (call["vm_name"], call["address"], call["release"]) == (NAME, vm.DEFAULT_ADDRESS, vm.DEFAULT_RELEASE)
    assert (call["memory"], call["vcpus"], call["disk_size"]) == (vm.DEFAULT_MEMORY, vm.DEFAULT_VCPUS, vm.DEFAULT_DISK_SIZE)


def test_a_failed_create_stops_the_run(tool):
    tool.create.result = False

    with pytest.raises(SystemExit):
        tool.main("create")
    assert tool.errors == ["Unable to create the virtual machine"]
    assert tool.infos == []


def test_destroy_names_the_machine(tool):
    tool.main("destroy", "-n", "guest", "-x")

    assert tool.destroy.calls == [{"vm_name": "guest", "verbose": False, "pretend_run": False, "exit_on_failure": True}]


@pytest.mark.parametrize("action", ["snapshot", "revert"])
def test_snapshot_actions_pass_the_snapshot_name(tool, action):
    tool.main(action, "-s", "clean")

    recorder = getattr(tool, action)
    assert recorder.values("vm_name") == [NAME]
    assert recorder.values("snapshot_name") == ["clean"]


def test_snapshots_are_listed_one_per_line(tool):
    tool.main("snapshots")

    assert tool.infos == ["clean", "after-tls"]


def test_ip_prints_the_address(tool, capsys):
    tool.main("ip", "-n", "guest")

    assert capsys.readouterr().out == "192.168.122.10\n"
    assert tool.ip.calls == [{"_args": ("guest",), "verbose": False}]


def test_ip_without_an_address_stops_the_run(tool, capsys):
    tool.ip.result = None

    with pytest.raises(SystemExit):
        tool.main("ip")
    assert tool.errors == ["No address yet for '%s'" % NAME]
    assert capsys.readouterr().out == ""


def test_console_attaches_through_virsh(tool):
    tool.main("console", "-n", "guest")

    assert tool.console.values("cmd") == [["virsh", "console", "guest"]]


def test_hosts_points_the_domain_at_the_guest(tool):
    tool.main("hosts", "-d", "example.test")

    assert tool.set_hosts.calls == [{
        "address": "192.168.122.10",
        "domain": "example.test",
        "sudo": True,
        "verbose": True,
        "pretend_run": False,
        "exit_on_failure": False}]
    assert tool.remove_hosts.calls == []


def test_hosts_without_an_address_writes_nothing(tool):
    tool.ip.result = ""

    with pytest.raises(SystemExit):
        tool.main("hosts")
    assert tool.set_hosts.calls == []


def test_hosts_remove_drops_the_managed_block(tool):
    tool.main("hosts", "--remove", "-p")

    assert tool.remove_hosts.calls == [{"sudo": True, "verbose": True, "pretend_run": True, "exit_on_failure": False}]
    assert tool.ip.calls == []


def test_an_unknown_action_stops_the_run(tool):
    with pytest.raises(SystemExit):
        tool.main("reboot")
    assert tool.errors == ["Unknown action 'reboot'"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, testvm)
