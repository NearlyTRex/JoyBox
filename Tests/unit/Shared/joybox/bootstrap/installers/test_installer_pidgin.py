# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox import runoptions
from joybox.bootstrap.installers import installer_pidgin
from fakes import RecordingConnection


###########################################################
# Pidgin
###########################################################

def make(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.Pidgin(connection), connection


def make_verified(**kwargs):
    pidgin, connection = make(**kwargs)
    connection.command_output["sha256sum"] = f"{pidgin.oscar_sha256}  {pidgin.archive_path}"
    connection.command_output["--cflags purple"] = "-I/usr/include/libpurple -I/usr/include/glib-2.0"
    connection.command_output["--libs glib-2.0"] = "-lglib-2.0"
    return pidgin, connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    pidgin, _ = make()
    assert pidgin.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_plugins_go_in_the_per_user_plugin_directory(isolated_settings):
    pidgin, connection = make()
    plugin_dir = os.path.join(os.path.expanduser("~"), ".purple", "plugins")
    assert pidgin.get_plugin_dir() == plugin_dir
    assert pidgin.get_plugin_paths() == [
        os.path.join(plugin_dir, "libaim.so"),
        os.path.join(plugin_dir, "libicq.so")]


def test_status_follows_each_plugin(isolated_settings):
    pidgin, connection = make()
    assert not pidgin.is_installed()
    assert pidgin.get_package_status() == {"installed": [], "missing": ["pidgin-aim", "pidgin-icq"]}

    connection.existing_paths.add(pidgin.get_plugin_paths()[0])
    assert not pidgin.is_installed()
    assert pidgin.get_package_status() == {"installed": ["pidgin-aim"], "missing": ["pidgin-icq"]}

    connection.existing_paths.add(pidgin.get_plugin_paths()[1])
    assert pidgin.is_installed()


def test_the_source_url_is_pinned(isolated_settings):
    pidgin, _ = make()
    assert pidgin.get_source_url().endswith(f"/{pidgin.oscar_version}/pidgin-{pidgin.oscar_version}.tar.bz2")


def test_install_builds_both_plugins_and_cleans_up(isolated_settings):
    pidgin, connection = make_verified()

    assert pidgin.install()
    assert connection.downloads == [(pidgin.get_source_url(), pidgin.archive_path)]
    assert connection.ran("-xjf", pidgin.archive_path, "-C", pidgin.build_dir)

    for protocol in installer_pidgin.OSCAR_PROTOCOLS:
        assert connection.ran(
            "gcc", "-fvisibility=hidden", "-I/usr/include/libpurple",
            f"oscar/lib{protocol}.c", f"oscar/oscar.c", f"lib{protocol}.so", "-lglib-2.0")

    built = [(os.path.join(pidgin.build_dir, f"lib{p}.so"), path)
        for p, path in zip(installer_pidgin.OSCAR_PROTOCOLS, pidgin.get_plugin_paths())]
    assert connection.moved == built
    assert all((path, "644") in connection.permissions for path in pidgin.get_plugin_paths())
    assert connection.removed_paths[-2:] == [pidgin.archive_path, pidgin.build_dir]


def test_install_supplies_the_private_headers(isolated_settings):
    pidgin, connection = make_verified()

    assert pidgin.install()
    include_dir = os.path.join(pidgin.build_dir, "include")
    assert (os.path.join(pidgin.build_dir, f"pidgin-{pidgin.oscar_version}", "libpurple", "internal.h"),
        os.path.join(include_dir, "internal.h")) in connection.copied
    config_header = connection.written(os.path.join(include_dir, "config.h"))
    assert f'#define VERSION "{pidgin.oscar_version}"' in config_header
    assert "#define ENABLE_NLS 1" in config_header


def test_install_needs_the_libpurple_headers(isolated_settings):
    pidgin, connection = make_verified(return_codes = {"--exists purple": 1})

    assert not pidgin.install()
    assert connection.downloads == []


def test_a_checksum_mismatch_fails_the_install(isolated_settings):
    pidgin, connection = make_verified()
    connection.command_output["sha256sum"] = f"{'0' * 64}  {pidgin.archive_path}"

    assert not pidgin.install()
    assert not connection.ran("-xjf")
    assert connection.removed_paths[-2:] == [pidgin.archive_path, pidgin.build_dir]


def test_a_failed_extract_fails_the_install(isolated_settings):
    pidgin, connection = make_verified(return_codes = {"-xjf": 1})

    assert not pidgin.install()
    assert not connection.ran("gcc")
    assert connection.removed_paths[-2:] == [pidgin.archive_path, pidgin.build_dir]


def test_a_failed_build_fails_the_install(isolated_settings):
    pidgin, connection = make_verified(return_codes = {"libicq.c": 1})

    assert not pidgin.install()
    assert connection.moved == []
    assert connection.removed_paths[-2:] == [pidgin.archive_path, pidgin.build_dir]


def test_a_pretend_run_skips_the_checksum(isolated_settings):
    flags = runoptions.RunFlags(verbose = False, pretend_run = True)
    connection = RecordingConnection(flags = flags)
    pidgin = installers.Pidgin(connection, flags = flags)

    assert pidgin.is_archive_verified()
    assert not connection.ran("sha256sum")


def test_uninstall_removes_present_plugins(isolated_settings):
    pidgin, connection = make()
    connection.existing_paths.add(pidgin.get_plugin_paths()[1])
    assert pidgin.uninstall()
    assert connection.removed_paths == [pidgin.get_plugin_paths()[1]]
