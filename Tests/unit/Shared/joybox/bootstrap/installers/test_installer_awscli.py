# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection

AWS_BINARY = "/usr/local/bin/aws"
ZIP_PATH = "/tmp/awscli-install/awscliv2.zip"


def build(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.AwsCli(connection), connection


###########################################################
# Status
###########################################################

def test_only_local_ubuntu_is_supported(isolated_settings):
    awscli, _ = build()
    assert awscli.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_status_follows_the_binary(isolated_settings):
    awscli, _ = build()
    assert not awscli.is_installed()
    assert awscli.get_package_status() == {"installed": [], "missing": ["aws-cli"]}

    awscli, _ = build(existing_paths = [AWS_BINARY])
    assert awscli.is_installed()
    assert awscli.get_package_status() == {"installed": ["aws-cli"], "missing": []}


###########################################################
# Install
###########################################################

def test_fresh_install_runs_the_installer_without_update(isolated_settings):
    awscli, connection = build()
    assert awscli.install()
    assert connection.ran("install", "-y", "unzip", "curl")
    assert connection.downloads == [("https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip", ZIP_PATH)]
    assert connection.ran("-q", ZIP_PATH, "-d", "/tmp/awscli-install")
    assert "/tmp/awscli-install/aws/install" in connection.command_strings()
    assert connection.ran("aws --version")
    assert connection.removed_paths[-1] == "/tmp/awscli-install"


def test_existing_install_is_updated_in_place(isolated_settings):
    awscli, connection = build(existing_paths = [AWS_BINARY])
    assert awscli.install()
    assert connection.ran("aws/install --update")


@pytest.mark.parametrize("fragment", [
    "unzip curl",
    "awscliv2.zip -d",
    "aws/install",
    "aws --version",
])
def test_a_failing_step_stops_the_install(isolated_settings, fragment):
    awscli, connection = build(return_codes = {fragment: 1})
    assert not awscli.install()
    assert connection.ran(fragment)


def test_a_failed_step_after_download_cleans_up(isolated_settings):
    awscli, connection = build(return_codes = {"aws/install": 1})
    assert not awscli.install()
    assert connection.removed_paths[-1] == "/tmp/awscli-install"


def test_a_missing_download_stops_before_extracting(isolated_settings):
    awscli, connection = build()
    connection.download_file = lambda url, dest, sudo = False: True
    assert not awscli.install()
    assert not connection.ran("awscliv2.zip -d")
    assert connection.removed_paths[-1] == "/tmp/awscli-install"


###########################################################
# Uninstall
###########################################################

def test_uninstall_removes_the_install_dir_and_symlinks(isolated_settings):
    awscli, connection = build(existing_paths = ["/usr/local/aws-cli"])
    assert awscli.uninstall()
    assert connection.removed_paths == ["/usr/local/aws-cli", AWS_BINARY, "/usr/local/bin/aws_completer"]
    assert all(call[2]["sudo"] for call in connection.called("remove_file_or_directory"))


def test_uninstall_without_an_install_dir_still_removes_symlinks(isolated_settings):
    awscli, connection = build()
    assert awscli.uninstall()
    assert connection.removed_paths == [AWS_BINARY, "/usr/local/bin/aws_completer"]
