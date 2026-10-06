# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_dconf
from joybox import runoptions
from fakes import RecordingConnection


###########################################################
# Dconf
#
# Settings apply only where their schema exists, so a desktop without
# Cinnamon is left alone rather than failing.
###########################################################

SETTING = installer_dconf.DCONF_SETTINGS[0]
SCHEMAS = f"org.gnome.desktop.interface\n{SETTING['schema']}\n"
GET_COMMAND = f"gsettings get {SETTING['schema']} {SETTING['key']}"


def make(schemas = SCHEMAS, current = None, pretend_run = False, **kwargs):
    output = {"list-schemas": schemas}
    if current is not None:
        output[GET_COMMAND] = current
    connection = RecordingConnection(command_output = output, **kwargs)
    flags = runoptions.RunFlags(verbose = False, pretend_run = pretend_run)
    return installers.Dconf(connection, flags), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    dconf, _ = make()
    assert dconf.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_schema_presence_matches_whole_names(isolated_settings):
    dconf, _ = make()
    assert dconf.is_schema_present("a.b.c\nd.e", "d.e")
    assert not dconf.is_schema_present("a.b.c", "a.b")
    assert not dconf.is_schema_present(None, "a.b")


def test_no_gsettings_is_not_installed(isolated_settings):
    dconf, _ = make(schemas = "")
    assert not dconf.is_installed()


def test_a_differing_value_is_not_installed(isolated_settings):
    dconf, _ = make(current = "'fingers'\n")
    assert not dconf.is_installed()


def test_the_desired_value_is_installed(isolated_settings):
    dconf, _ = make(current = SETTING["value"] + "\n")
    assert dconf.is_installed()


def test_a_missing_schema_counts_as_installed(isolated_settings):
    dconf, connection = make(schemas = "org.gnome.desktop.interface\n")

    assert dconf.is_installed()
    assert not connection.ran("gsettings get")


def test_install_sets_each_value(isolated_settings):
    dconf, connection = make()

    assert dconf.install()
    assert connection.ran("gsettings set", SETTING["schema"], SETTING["key"], SETTING["value"])


def test_install_skips_a_missing_schema(isolated_settings):
    dconf, connection = make(schemas = "org.gnome.desktop.interface\n")

    assert dconf.install()
    assert not connection.ran("gsettings set")


def test_install_fails_without_gsettings(isolated_settings):
    dconf, _ = make(schemas = "")
    assert not dconf.install()


def test_a_pretend_run_without_gsettings_succeeds(isolated_settings):
    dconf, connection = make(schemas = "", pretend_run = True)

    assert dconf.install()
    assert not connection.ran("gsettings set")


def test_a_failed_set_fails_the_install(isolated_settings):
    dconf, _ = make(return_codes = {"gsettings set": 1})
    assert not dconf.install()


def test_uninstall_resets_present_schemas_only(isolated_settings):
    dconf, connection = make()
    assert dconf.uninstall()
    assert connection.ran("gsettings reset", SETTING["schema"], SETTING["key"])

    dconf, connection = make(schemas = "")
    assert dconf.uninstall()
    assert not connection.ran("gsettings reset")
