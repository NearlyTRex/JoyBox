# Imports
import ast
import os

# Third-party imports
import pytest

# Local imports
from fakes import RecordingConnection


###########################################################
# Remote components against the sudo grants
#
# On a real server the account's sudo covers apt-get and the manager scripts,
# nothing more, and remote sudo never prompts. A component needing anything
# else fails on the server and nowhere else, so it is caught here.
###########################################################

ENVIRONMENT_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "..", "..", "..",
    "Shared", "joybox", "bootstrap", "environments", "env_remote_ubuntu.py")


# The component names, read from the source so nothing is built while tests
# are collected
def read_component_names():
    with open(ENVIRONMENT_FILE, "r") as source:
        tree = ast.parse(source.read())
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                and any(isinstance(target, ast.Attribute) and target.attr == "available_components"
                        for target in node.targets)):
            return sorted(key.value for key in node.value.keys)
    return []


COMPONENTS = read_component_names()


def granted_programs(installer):
    programs = {installer.aptget_tool}
    for name in dir(installer):
        if name.endswith("_manager_tool"):
            programs.add(getattr(installer, name))
    return programs


def test_the_component_list_was_found():
    assert "nginx" in COMPONENTS and "wordpress" in COMPONENTS


@pytest.mark.parametrize("component", COMPONENTS)
def test_a_remote_component_needs_only_granted_sudo(isolated_settings, component):
    from joybox.bootstrap.environments import env_remote_ubuntu
    environment = env_remote_ubuntu.RemoteUbuntu(ssh_host = "server.test")
    installer = environment.available_components[component]
    connection = RecordingConnection()
    installer.connection = connection
    installer.install()

    privileged = {call[1][0][0] for call in connection.calls
                  if call[0].startswith("run_") and call[2].get("sudo")}
    privileged_io = sorted({call[0] for call in connection.calls
                            if not call[0].startswith("run_") and call[2].get("sudo")})
    assert privileged <= granted_programs(installer), sorted(privileged - granted_programs(installer))
    assert privileged_io == [], "sudo file operations are not granted: %s" % privileged_io
