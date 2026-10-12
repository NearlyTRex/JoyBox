# Imports
import os
import stat

# Third-party imports
import pytest


###########################################################
# Cockpit manager
#
# Cockpit manages networking through NetworkManager, so installing it moves
# the machine's netplan renderer over, and that move decides whether the
# machine still comes up on the network promptly after a reboot.
###########################################################

SCRIPT = "Bootstrap/managers/manager_cockpit.sh"
SOCKET_OVERRIDE = "/etc/systemd/system/cockpit.socket.d/joybox-listen.conf"
COCKPIT_NETPLAN = "/etc/netplan/99-cockpit.yaml"
POLKIT_RULE = "/etc/polkit-1/rules.d/50-cockpit-packagekit.rules"
CLOUD_NETPLAN = "/etc/netplan/50-cloud-init.yaml"


# Make systemctl fail for one action on one unit
def fail_systemctl(sandbox, action, unit):
    sandbox.stub("systemctl", script = (
        'for arg in "$@"; do [ "$arg" = "%s" ] && unit=1; done\n'
        '[ "$1" = "%s" ] && [ -n "${unit:-}" ] && exit 1\n'
        'exit 0\n') % (unit, action))


@pytest.fixture
def server(shell_sandbox):
    # What the cockpit packages bring with them; apt-get is a stub here
    os.makedirs(shell_sandbox.host_path(os.path.dirname(POLKIT_RULE)))
    shell_sandbox.write(CLOUD_NETPLAN, "network:\n  version: 2\n  ethernets:\n    enp1s0:\n      dhcp4: true\n")
    return shell_sandbox


def install(server):
    return server.run(SCRIPT, "install")


###########################################################
# Install
###########################################################

def test_install_succeeds(server):
    result = install(server)

    assert result.returncode == 0, result.stdout + result.stderr


def test_install_installs_network_manager_before_cockpit(server):
    install(server)

    installs = [call for call in server.calls("apt-get") if call[:1] == ["install"]]
    assert installs[0][-1] == "network-manager"
    assert "cockpit" in installs[1]


def test_cockpit_listens_on_loopback_only(server):
    # nginx's admin subdomain carries the TLS and rate limiting; a public 9090 would not
    install(server)

    override = server.read(SOCKET_OVERRIDE)
    assert "ListenStream=\nListenStream=127.0.0.1:9090" in override
    assert server.ran("systemctl", "daemon-reload")
    assert server.ran("systemctl", "restart", "cockpit.socket")


def test_without_a_renderer_a_netplan_file_hands_networking_to_network_manager(server):
    install(server)

    assert server.read(COCKPIT_NETPLAN) == "network:\n  version: 2\n  renderer: NetworkManager\n"
    assert stat.S_IMODE(os.stat(server.host_path(COCKPIT_NETPLAN)).st_mode) == 0o600
    assert server.ran("netplan", "apply")


def test_an_existing_renderer_is_switched_in_place(server):
    server.write(CLOUD_NETPLAN, "network:\n  version: 2\n  renderer: networkd\n")

    install(server)

    assert "renderer: NetworkManager" in server.read(CLOUD_NETPLAN)
    assert not server.exists(COCKPIT_NETPLAN)


def test_install_moves_boot_waiting_to_network_manager(server):
    # networkd no longer manages any link, so its wait-online would hold
    # every boot until it timed out
    install(server)

    assert server.ran("systemctl", "disable", "systemd-networkd-wait-online.service")
    assert server.ran("systemctl", "enable", "NetworkManager-wait-online.service")


def test_a_public_9090_rule_is_removed(server):
    server.stub("ufw", stdout = "Status: active\n9090/tcp ALLOW Anywhere\n")

    install(server)

    assert server.ran("ufw", "--force", "delete", "allow", "9090/tcp")


def test_no_9090_rule_leaves_the_firewall_alone(server):
    install(server)

    assert not server.ran("ufw", "--force", "delete")


def test_package_kit_may_refresh_for_sudo_users(server):
    install(server)

    rule = server.read(POLKIT_RULE)
    assert "org.freedesktop.packagekit.system-update" in rule
    assert 'subject.isInGroup("sudo")' in rule


@pytest.mark.parametrize("action, unit, message", [
    ("enable", "NetworkManager", "Failed to enable and start NetworkManager"),
    ("enable", "cockpit.socket", "Failed to enable and start cockpit.socket"),
    ("restart", "cockpit.socket", "Failed to enable and start cockpit.socket"),
    ("enable", "NetworkManager-wait-online.service", "Failed to enable NetworkManager-wait-online.service"),
])
def test_a_service_that_will_not_start_stops_the_install(server, action, unit, message):
    fail_systemctl(server, action, unit)

    result = install(server)

    assert result.returncode == 1
    assert message in result.stdout


def test_a_failed_netplan_apply_stops_before_the_wait_services_change(server):
    server.stub("netplan", code = 1)

    result = install(server)

    assert result.returncode == 1
    assert "Netplan failed" in result.stdout
    assert not server.ran("systemctl", "disable", "systemd-networkd-wait-online.service")


###########################################################
# Uninstall
###########################################################

def uninstall(server):
    return server.run(SCRIPT, "uninstall")


def test_uninstall_reverses_the_install(server):
    install(server)

    result = uninstall(server)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not server.exists(COCKPIT_NETPLAN)
    assert not server.exists(POLKIT_RULE)
    assert not server.exists(os.path.dirname(SOCKET_OVERRIDE))
    assert server.ran("apt-get", "remove", "--purge", "-y", "network-manager")


def test_uninstall_gives_boot_waiting_back_to_networkd(server):
    uninstall(server)

    assert server.ran("systemctl", "disable", "NetworkManager-wait-online.service")
    assert server.ran("systemctl", "enable", "systemd-networkd-wait-online.service")


def test_uninstall_reapplies_netplan_only_when_it_removed_a_file(server):
    uninstall(server)
    assert not server.ran("netplan", "apply")

    server.write(COCKPIT_NETPLAN, "network:\n  renderer: NetworkManager\n")
    uninstall(server)
    assert server.ran("netplan", "apply")


def test_uninstall_closes_9090_on_an_active_firewall(server):
    server.stub("ufw", stdout = "Status: active\n")

    uninstall(server)

    assert server.ran("ufw", "delete", "allow", "9090/tcp")


###########################################################
# Usage
###########################################################

@pytest.mark.parametrize("args", [[], ["install", "extra"]])
def test_the_wrong_number_of_arguments_prints_usage(server, args):
    result = server.run(SCRIPT, *args)

    assert result.returncode == 1
    assert "Usage:" in result.stdout


def test_an_unknown_action_is_refused(server):
    result = server.run(SCRIPT, "reinstall")

    assert result.returncode == 1
    assert "Invalid command 'reinstall'" in result.stdout
