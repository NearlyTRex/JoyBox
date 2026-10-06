# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_node
from fakes import RecordingConnection


###########################################################
# Node (global npm packages)
###########################################################

CODEX = {"id": "@openai/codex", "name": "Codex CLI", "description": "agent", "category": "AI"}


def make(packages, **kwargs):
    connection = RecordingConnection(**kwargs)
    node = installers.Node(connection)
    node.get_packages = lambda: list(packages)
    return node, connection


def test_package_descriptors_fall_back_sensibly():
    assert installer_node.get_node_package_id({"name": "pnpm"}) == "pnpm"
    assert installer_node.get_node_package_id({}) == ""
    assert installer_node.get_node_package_info({"id": "pnpm"}) == {
        "id": "pnpm", "name": "pnpm", "description": "", "category": ""}
    assert installer_node.get_node_package_info(CODEX)["name"] == "Codex CLI"


def test_only_local_ubuntu_is_supported(isolated_settings):
    node, _ = make([])
    assert node.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_the_package_list_follows_the_environment_type(isolated_settings):
    node = installers.Node(RecordingConnection())
    node.set_environment_type(constants.EnvironmentType.LOCAL_UBUNTU)

    assert node.get_packages() == installer_node.packages.node[constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_needs_every_package(isolated_settings):
    node, connection = make([CODEX, {"id": "ccusage"}])
    assert node.is_installed()
    assert connection.ran("npm list -g @openai/codex")

    node, _ = make([CODEX, {"id": "ccusage"}], return_codes = {"list -g ccusage": 1})
    assert not node.is_installed()


def test_package_status_splits_installed_and_missing(isolated_settings):
    node, _ = make([CODEX, {"id": "ccusage"}], return_codes = {"list -g @openai": 1})
    assert node.get_package_status() == {"installed": ["ccusage"], "missing": ["Codex CLI"]}


def test_install_installs_only_missing_packages_as_root(isolated_settings):
    node, connection = make([CODEX, {"id": "ccusage"}], return_codes = {"list -g ccusage": 1})

    assert node.install()
    assert connection.ran("npm install -g ccusage")
    assert not connection.ran("npm install -g @openai/codex")
    assert all(call[2]["sudo"] for call in connection.called("run_blocking") if "install" in call[1][0])


def test_a_failed_install_stops(isolated_settings):
    node, connection = make([CODEX, {"id": "ccusage"}], return_codes = {"list -g": 1, "install -g @openai": 1})

    assert not node.install()
    assert not connection.ran("install -g ccusage")


def test_uninstall_removes_every_package(isolated_settings):
    node, connection = make([CODEX, {"id": "ccusage"}])

    assert node.uninstall()
    assert connection.ran("npm uninstall -g @openai/codex")
    assert connection.ran("npm uninstall -g ccusage")


def test_a_failed_uninstall_stops(isolated_settings):
    node, connection = make([CODEX, {"id": "ccusage"}], return_codes = {"uninstall -g @openai": 1})

    assert not node.uninstall()
    assert not connection.ran("uninstall -g ccusage")
