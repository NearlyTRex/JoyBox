# Local imports
from joybox.tools import perl
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Perl", "perl_exe", "perl")
    isolated_settings.set_value("Tools.Perl", "perl_install_dir", "/opt/perl/bin")

    tool = perl.Perl()

    assert tool.get_name() == "Perl"
    assert tool.get_config() == {"Perl": {"program": "/opt/perl/bin/perl"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Perl", "perl_exe", "perl")
    isolated_settings.set_value("Tools.Perl", "perl_install_dir", "$JOYBOX_TEST_ROOT/perl")

    assert perl.Perl().get_config()["Perl"]["program"] == "/srv/tools/perl/perl"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, perl.Perl())
