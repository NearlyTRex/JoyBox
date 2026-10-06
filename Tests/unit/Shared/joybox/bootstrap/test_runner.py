# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
from joybox.bootstrap import runner
from joybox import runoptions
from joybox import serverinfo


###########################################################
# Environment construction
#
# A remote run takes its connection from the server entry, and the domain is
# required unless the caller is only listing what the server would open.
###########################################################

class RecordingEnvironment:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def get_public_ports(self):
        return ["5190"]


@pytest.fixture
def built(monkeypatch):
    monkeypatch.setattr(runner.environments, "LocalUbuntu", lambda **kwargs: ("local", kwargs))
    monkeypatch.setattr(runner.environments, "RemoteUbuntu", lambda **kwargs: RecordingEnvironment(**kwargs))


def configure_server(settings, index, host = "server.test", domain = "example.test"):
    settings.set_value("UserData.Servers", f"server_{index}_host", host)
    settings.set_value("UserData.Servers", f"server_{index}_user", "deploy")
    settings.set_value("UserData.Servers", f"server_{index}_domain_name", domain)


def test_a_local_environment_gets_the_flags_and_no_shell(isolated_settings, built):
    flags = runoptions.RunFlags(verbose = False)
    kind, kwargs = runner.create_environment(constants.EnvironmentType.LOCAL_UBUNTU, flags = flags)

    assert kind == "local"
    assert kwargs["flags"] is flags
    assert not kwargs["options"].shell


def test_default_flags_are_supplied(isolated_settings, built):
    _, kwargs = runner.create_environment(constants.EnvironmentType.LOCAL_UBUNTU)
    assert isinstance(kwargs["flags"], runoptions.RunFlags)


def test_a_remote_environment_connects_to_the_server_entry(isolated_settings, built):
    configure_server(isolated_settings, 1)
    environment = runner.create_environment(constants.EnvironmentType.REMOTE_UBUNTU, server_index = 1)

    assert environment.kwargs["ssh_host"] == "server.test"
    assert environment.kwargs["ssh_user"] == "deploy"
    assert environment.kwargs["options"].shell
    assert serverinfo.get_selected_server().get_index() == 1


def test_an_explicit_key_wins_over_the_server_entry(isolated_settings, built):
    configure_server(isolated_settings, 1)
    isolated_settings.set_value("UserData.Servers", "server_1_key_filepath", "/keys/entry")
    environment = runner.create_environment(
        constants.EnvironmentType.REMOTE_UBUNTU, server_index = 1, ssh_key_filepath = "/keys/explicit")

    assert environment.kwargs["ssh_key_filepath"] == "/keys/explicit"


def test_a_remote_environment_without_a_server_index_uses_no_entry(isolated_settings, built):
    environment = runner.create_environment(constants.EnvironmentType.REMOTE_UBUNTU)

    assert "ssh_host" not in environment.kwargs


def test_an_unconfigured_server_is_refused(isolated_settings, built):
    assert runner.create_environment(constants.EnvironmentType.REMOTE_UBUNTU, server_index = 7) is None


def test_a_server_without_a_domain_is_refused(isolated_settings, built):
    configure_server(isolated_settings, 1, domain = "")

    assert runner.create_environment(constants.EnvironmentType.REMOTE_UBUNTU, server_index = 1) is None
    assert serverinfo.get_selected_server().get_index() == 0


def test_listing_ports_does_not_need_a_domain(isolated_settings, built):
    configure_server(isolated_settings, 1, domain = "")
    assert runner.get_public_ports(1) == ["5190"]


def test_an_unknown_server_has_no_public_ports(isolated_settings, built):
    assert runner.get_public_ports(7) == []


def test_an_environment_type_without_a_runner_is_refused(isolated_settings, built):
    assert runner.create_environment(constants.EnvironmentType.LOCAL_WINDOWS) is None
