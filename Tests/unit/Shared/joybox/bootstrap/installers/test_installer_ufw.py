# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# Ufw
#
# A machine only opens the ports of what it serves, and only to the LAN.
###########################################################

SUBNET = "192.168.1.0/24"


def make(isolated_settings, streaming_host = True, subnet = SUBNET, **kwargs):
    isolated_settings.set_value("Tools.Sunshine", "sunshine_streaming_host", str(streaming_host))
    isolated_settings.set_value("Tools.Sunshine", "sunshine_allowed_subnet", subnet)
    connection = RecordingConnection(**kwargs)
    return installers.Ufw(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    ufw, _ = make(isolated_settings)
    assert ufw.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_a_streaming_host_opens_the_sunshine_ports_to_the_lan_only(isolated_settings):
    ufw, connection = make(isolated_settings)

    assert ufw.install()

    assert connection.ran("ufw allow from 192.168.1.0/24 to any port 47984,47989,47990,48010 proto tcp comment joybox-sunshine-tcp")
    assert connection.ran("ufw allow from 192.168.1.0/24 to any port 47998:48000 proto udp comment joybox-sunshine-udp")
    assert all(call[2]["sudo"] for call in connection.called("run_blocking"))


def test_other_machines_open_nothing(isolated_settings):
    ufw, connection = make(isolated_settings, streaming_host = False)

    assert ufw.is_installed()
    assert ufw.install()

    assert connection.commands == []


def test_a_missing_subnet_fails_rather_than_opening_to_everyone(isolated_settings):
    ufw, connection = make(isolated_settings, subnet = "")

    assert not ufw.install()

    assert not connection.ran("ufw allow")


def test_without_ufw_there_is_nothing_to_open(isolated_settings):
    ufw, connection = make(isolated_settings, return_codes = {"command -v ufw": 1})

    assert ufw.install()

    assert not connection.ran("ufw allow")


def test_a_failed_rule_stops_the_install(isolated_settings):
    ufw, connection = make(isolated_settings, return_codes = {"sunshine-tcp": 1})

    assert not ufw.install()

    assert not connection.ran("sunshine-udp")


def test_installed_once_ufw_lists_every_enabled_rule(isolated_settings):
    status = "47998:48000/udp ALLOW 192.168.1.0/24 # joybox-sunshine-udp"
    ufw, _ = make(isolated_settings, command_output = {"ufw status": status})
    assert not ufw.is_installed()

    status += "\n47984,47989,47990,48010/tcp ALLOW 192.168.1.0/24 # joybox-sunshine-tcp"
    ufw, _ = make(isolated_settings, command_output = {"ufw status": status})
    assert ufw.is_installed()


def test_uninstall_deletes_every_rule_even_when_turned_off(isolated_settings):
    ufw, connection = make(isolated_settings, streaming_host = False)

    assert ufw.uninstall()

    assert connection.ran("ufw delete allow from 192.168.1.0/24 to any port 47984,47989,47990,48010 proto tcp")
    assert connection.ran("ufw delete allow from 192.168.1.0/24 to any port 47998:48000 proto udp")
