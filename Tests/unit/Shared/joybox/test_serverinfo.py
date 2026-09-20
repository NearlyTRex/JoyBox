# Imports
import pytest

# Local imports
from joybox import serverinfo
from joybox.connection import ConnectionLocal, ConnectionSSH


###########################################################
# Server info
#
# One entry under [UserData.Servers], read by index. bootstrap.py and the
# verification tools both build their connection from this, so the shape of
# an entry is pinned here.
###########################################################

SECTION = serverinfo.SECTION


@pytest.fixture
def server(isolated_settings):
    isolated_settings.set_value(SECTION, "server_0_host", "10.0.0.5")
    isolated_settings.set_value(SECTION, "server_0_port", "2222")
    isolated_settings.set_value(SECTION, "server_0_user", "deploy")
    isolated_settings.set_value(SECTION, "server_0_pass", "hunter2")
    isolated_settings.set_value(SECTION, "server_0_key_filepath", "/home/deploy/.ssh/id_ed25519")
    return isolated_settings


###########################################################
# Reading an entry
###########################################################

def test_a_populated_entry_reads_back_every_field(server):
    info = serverinfo.ServerInfo(0)

    assert info.get_index() == 0
    assert info.get_host() == "10.0.0.5"
    assert info.get_port() == 2222
    assert info.get_user() == "deploy"
    assert info.get_password() == "hunter2"
    assert info.get_key_filepath() == "/home/deploy/.ssh/id_ed25519"


def test_an_entry_is_read_by_index(server):
    server.set_value(SECTION, "server_1_host", "10.0.0.6")

    assert serverinfo.ServerInfo(0).get_host() == "10.0.0.5"
    assert serverinfo.ServerInfo(1).get_host() == "10.0.0.6"


def test_an_index_may_be_given_as_a_string(server):
    assert serverinfo.ServerInfo("0").get_host() == "10.0.0.5"


def test_an_empty_field_reads_back_as_none(isolated_settings):
    isolated_settings.set_value(SECTION, "server_0_host", "10.0.0.5")

    info = serverinfo.ServerInfo(0)

    assert info.get_user() is None
    assert info.get_password() is None


def test_an_entry_without_a_key_filepath_is_still_usable(isolated_settings):
    # Configs written before key auth existed carry no such field
    isolated_settings.set_value(SECTION, "server_0_host", "10.0.0.5")
    isolated_settings.set_value(SECTION, "server_0_pass", "hunter2")

    info = serverinfo.ServerInfo(0)

    assert info.is_configured()
    assert info.get_key_filepath() is None
    assert info.get_password() == "hunter2"


def test_an_unknown_index_reads_back_empty(server):
    info = serverinfo.ServerInfo(9)

    assert info.get_host() is None
    assert not info.is_configured()


###########################################################
# The port default
#
# A missing port must not reach paramiko as None or "".
###########################################################

def test_a_missing_port_falls_back_to_the_ssh_default(isolated_settings):
    isolated_settings.set_value(SECTION, "server_0_host", "10.0.0.5")

    assert serverinfo.ServerInfo(0).get_port() == serverinfo.DEFAULT_PORT


def test_an_empty_port_falls_back_to_the_ssh_default(isolated_settings):
    isolated_settings.set_value(SECTION, "server_0_host", "10.0.0.5")
    isolated_settings.set_value(SECTION, "server_0_port", "")

    assert serverinfo.ServerInfo(0).get_port() == 22


def test_a_configured_port_is_an_integer(server):
    port = serverinfo.ServerInfo(0).get_port()

    assert isinstance(port, int)
    assert port == 2222


###########################################################
# Configured
###########################################################

def test_an_entry_is_configured_when_it_names_a_host(server):
    assert serverinfo.ServerInfo(0).is_configured() is True


def test_an_entry_with_a_user_but_no_host_is_not_configured(isolated_settings):
    isolated_settings.set_value(SECTION, "server_0_user", "deploy")

    assert serverinfo.ServerInfo(0).is_configured() is False


###########################################################
# Connection options
###########################################################

def test_connection_options_carry_every_ssh_field(server):
    options = serverinfo.ServerInfo(0).get_connection_options()

    assert options == {
        "ssh_host": "10.0.0.5",
        "ssh_port": 2222,
        "ssh_user": "deploy",
        "ssh_password": "hunter2",
        "ssh_key_filepath": "/home/deploy/.ssh/id_ed25519",
    }


def test_connection_options_are_exactly_what_a_ssh_connection_takes(server):
    # A rename on either side would otherwise surface only at deploy time
    connection = ConnectionSSH(**serverinfo.ServerInfo(0).get_connection_options())

    assert connection.ssh_host == "10.0.0.5"
    assert connection.ssh_port == 2222


###########################################################
# The domain
###########################################################

def test_the_domain_is_read_from_the_server_section(isolated_settings):
    isolated_settings.set_value(SECTION, "domain_name", "example.test")

    assert serverinfo.get_domain_name() == "example.test"


def test_an_unset_domain_reads_back_as_none(isolated_settings):
    isolated_settings.set_value(SECTION, "domain_name", "")

    assert serverinfo.get_domain_name() is None


###########################################################
# Building a connection
###########################################################

def test_no_server_index_means_this_machine(server):
    connection = serverinfo.get_connection()

    assert isinstance(connection, ConnectionLocal)


def test_a_server_index_means_ssh(server):
    connection = serverinfo.get_connection(server_index = 0)

    assert isinstance(connection, ConnectionSSH)
    assert connection.ssh_host == "10.0.0.5"
    assert connection.ssh_user == "deploy"
    assert connection.ssh_key_filepath == "/home/deploy/.ssh/id_ed25519"


def test_an_unconfigured_server_index_builds_no_connection(server):
    assert serverinfo.get_connection(server_index = 9) is None


def test_flags_are_carried_into_the_connection(server):
    from joybox import runoptions

    flags = runoptions.RunFlags(pretend_run = True)

    connection = serverinfo.get_connection(server_index = 0, flags = flags)

    assert connection.flags.pretend_run


def test_a_local_connection_also_carries_flags(isolated_settings):
    from joybox import runoptions

    flags = runoptions.RunFlags(pretend_run = True)

    connection = serverinfo.get_connection(flags = flags)

    assert connection.flags.pretend_run
