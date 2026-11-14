# Local imports
from joybox.tools import fuseiso
from tools_helpers import assert_installs_nothing


def set_programs(settings, fuseiso_dir, fusermount_dir):
    settings.set_value("Tools.FuseISO", "fuseiso_exe", "fuseiso")
    settings.set_value("Tools.FuseISO", "fusermount_exe", "fusermount")
    settings.set_value("Tools.FuseISO", "fuseiso_install_dir", fuseiso_dir)
    settings.set_value("Tools.FuseISO", "fusermount_install_dir", fusermount_dir)


def test_both_programs_are_linux_only(isolated_settings):
    set_programs(isolated_settings, "/usr/bin", "/usr/local/bin")

    tool = fuseiso.FuseISO()

    assert tool.get_name() == "FuseISO"
    assert tool.get_config() == {
        "FuseISO": {"program": {"windows": None, "linux": "/usr/bin/fuseiso"}},
        "FUserMount": {"program": {"windows": None, "linux": "/usr/local/bin/fusermount"}},
    }


def test_variables_in_the_install_dirs_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/fuse")
    set_programs(isolated_settings, "$JOYBOX_TEST_ROOT/iso", "$JOYBOX_TEST_ROOT/mount")

    config = fuseiso.FuseISO().get_config()

    assert config["FuseISO"]["program"]["linux"] == "/srv/fuse/iso/fuseiso"
    assert config["FUserMount"]["program"]["linux"] == "/srv/fuse/mount/fusermount"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, fuseiso.FuseISO())
