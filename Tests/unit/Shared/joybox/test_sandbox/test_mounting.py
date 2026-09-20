# Imports
import getpass
import os
import pytest

# Local imports
from joybox import commandoptions, config, sandbox
from sandbox_helpers import options, WINE, SANDBOXIE, NEITHER, PREFIX


###########################################################
# Mounting into a prefix
#
# A mount is a symlink at the next free drive letter inside the prefix. Two
# mounts on the same letter hide the first, and a drive that is never released
# leaks letters until there are none left.
###########################################################

@pytest.fixture
def wine_prefix(tmp_path):
    prefix = tmp_path / "prefix"
    (prefix / "dosdevices").mkdir(parents = True)
    (prefix / "drive_c").mkdir()
    return options(wine = True, prefix_dir = str(prefix))


def drive(prefix_options, letter):
    return sandbox.get_real_drive_path(prefix_options, letter)


def test_the_first_free_drive_letter_is_offered(wine_prefix):
    found = sandbox.find_first_available_real_drive_path(wine_prefix)

    assert found == drive(wine_prefix, config.drives_regular[0])


def test_a_taken_drive_letter_is_skipped(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()
    os.symlink(str(source), drive(wine_prefix, config.drives_regular[0]))

    found = sandbox.find_first_available_real_drive_path(wine_prefix)

    assert found == drive(wine_prefix, config.drives_regular[1])


def test_a_full_prefix_offers_no_drive(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()
    for letter in config.drives_regular:
        os.symlink(str(source), drive(wine_prefix, letter))

    assert sandbox.find_first_available_real_drive_path(wine_prefix) is None


def test_a_directory_is_mounted_on_the_first_free_drive(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()

    assert sandbox.mount_directory(str(source), wine_prefix) is True
    assert os.path.realpath(drive(wine_prefix, config.drives_regular[0])) == str(source)


def test_a_second_mount_takes_the_next_drive(wine_prefix, tmp_path):
    first = tmp_path / "first"
    first.mkdir()
    second = tmp_path / "second"
    second.mkdir()

    sandbox.mount_directory(str(first), wine_prefix)
    sandbox.mount_directory(str(second), wine_prefix)

    assert os.path.realpath(drive(wine_prefix, config.drives_regular[1])) == str(second)


def test_a_mount_into_a_full_prefix_reports_failure(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()
    for letter in config.drives_regular:
        os.symlink(str(source), drive(wine_prefix, letter))

    assert sandbox.mount_directory(str(source), wine_prefix) is False


def test_a_mounted_directory_is_found_by_its_source(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()
    sandbox.mount_directory(str(source), wine_prefix)

    found = sandbox.find_first_taken_real_drive_path(str(source), wine_prefix)

    assert found == drive(wine_prefix, config.drives_regular[0])


def test_an_unmounted_directory_is_not_found(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()

    assert sandbox.find_first_taken_real_drive_path(str(source), wine_prefix) is None


def test_unmounting_releases_the_drive_letter(wine_prefix, tmp_path):
    # The symlink is what holds the letter; leaving it in place means the next
    # mount lands on a different drive than the game expects.
    source = tmp_path / "disc"
    source.mkdir()
    sandbox.mount_directory(str(source), wine_prefix)

    assert sandbox.unmount_directory(str(source), wine_prefix) is True
    assert not os.path.islink(drive(wine_prefix, config.drives_regular[0]))


def test_unmounting_keeps_the_source_directory(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()
    (source / "data.bin").write_text("payload")
    sandbox.mount_directory(str(source), wine_prefix)

    sandbox.unmount_directory(str(source), wine_prefix)

    assert (source / "data.bin").read_text() == "payload"


def test_unmounting_frees_the_letter_for_the_next_mount(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    sandbox.mount_directory(str(source), wine_prefix)
    sandbox.unmount_directory(str(source), wine_prefix)

    sandbox.mount_directory(str(other), wine_prefix)

    assert os.path.realpath(drive(wine_prefix, config.drives_regular[0])) == str(other)


def test_unmounting_something_never_mounted_reports_failure(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()

    assert sandbox.unmount_directory(str(source), wine_prefix) is False


def test_every_drive_is_released_at_once(wine_prefix, tmp_path):
    first = tmp_path / "first"
    first.mkdir()
    second = tmp_path / "second"
    second.mkdir()
    sandbox.mount_directory(str(first), wine_prefix)
    sandbox.mount_directory(str(second), wine_prefix)

    assert sandbox.unmount_all_mounted_drives(wine_prefix) is True
    assert not any(
        os.path.islink(drive(wine_prefix, letter)) for letter in config.drives_regular)


def test_releasing_every_drive_keeps_the_sources(wine_prefix, tmp_path):
    source = tmp_path / "disc"
    source.mkdir()
    sandbox.mount_directory(str(source), wine_prefix)

    sandbox.unmount_all_mounted_drives(wine_prefix)

    assert source.is_dir()


def test_a_disc_image_is_mounted_after_it_is_attached(wine_prefix, tmp_path, monkeypatch):
    # The image has to be attached before there is anything to symlink.
    order = []
    mount_dir = tmp_path / "mount"
    mount_dir.mkdir()
    image = tmp_path / "Game.chd"
    image.write_text("")

    import joybox.chd as chd
    monkeypatch.setattr(chd, "mount_disc_chd", lambda **kwargs: order.append("attach") or True)
    monkeypatch.setattr(sandbox, "mount_directory", lambda **kwargs: order.append("symlink") or True)

    assert sandbox.mount_disc_image(str(image), str(mount_dir), wine_prefix) is True
    assert order == ["attach", "symlink"]


def test_an_image_that_will_not_attach_is_not_mounted(wine_prefix, tmp_path, monkeypatch):
    mount_dir = tmp_path / "mount"
    mount_dir.mkdir()
    image = tmp_path / "Game.chd"
    image.write_text("")

    import joybox.chd as chd
    monkeypatch.setattr(chd, "mount_disc_chd", lambda **kwargs: False)

    def fail(**kwargs):
        raise AssertionError("nothing may be symlinked before the image attaches")

    monkeypatch.setattr(sandbox, "mount_directory", fail)

    assert sandbox.mount_disc_image(str(image), str(mount_dir), wine_prefix) is False


def test_a_disc_image_is_detached_after_it_is_unmounted(wine_prefix, tmp_path, monkeypatch):
    # Detaching while the drive letter still points at it leaves a dead mount.
    order = []
    mount_dir = tmp_path / "mount"
    mount_dir.mkdir()
    image = tmp_path / "Game.chd"
    image.write_text("")

    import joybox.chd as chd
    monkeypatch.setattr(sandbox, "unmount_directory", lambda **kwargs: order.append("symlink") or True)
    monkeypatch.setattr(chd, "unmount_disc_chd", lambda **kwargs: order.append("detach") or True)

    assert sandbox.unmount_disc_image(str(image), str(mount_dir), wine_prefix) is True
    assert order == ["symlink", "detach"]
