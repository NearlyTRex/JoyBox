# Imports
import pytest

# Local imports
from joybox import install


###########################################################
# Install images
#
# A snapshot of a Wine prefix after an installer has run, packed for the
# locker. These cover the paths that finish before the archiver runs; the
# round trips through 7-Zip are integration tests.
###########################################################

def make_tree(root, *relative_paths):
    for relative in relative_paths:
        target = root / relative
        target.parent.mkdir(parents = True, exist_ok = True)
        target.write_text("content of %s\n" % relative)
    return root


@pytest.fixture
def prefix(tmp_path):
    root = tmp_path / "prefix"
    root.mkdir()
    return make_tree(
        root,
        "Program Files/Game/game.exe",
        "Program Files/Game/data/assets.pak",
        "ProgramData/Game/settings.ini")


###########################################################
# Packing
###########################################################

def test_an_empty_directory_packs_nothing(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()
    image = tmp_path / "install.7z"

    assert install.pack_install_image(str(source), str(image)) is False
    assert not image.exists()


def test_a_missing_directory_packs_nothing(tmp_path):
    image = tmp_path / "install.7z"

    assert install.pack_install_image(str(tmp_path / "absent"), str(image)) is False


def test_pretending_packs_nothing(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image), pretend_run = True)

    assert not image.exists()


def test_a_prefix_of_only_ignored_paths_packs_nothing(tmp_path):
    # Everything the Windows layer leaves behind, plus the user's own profile.
    source = tmp_path / "prefix"
    source.mkdir()
    make_tree(source, "windows/system32/kernel32.dll", "users/someone/file.txt")
    image = tmp_path / "install.7z"

    assert install.pack_install_image(str(source), str(image)) is False
    assert not image.exists()


###########################################################
# Unpacking
###########################################################

def test_unpacking_a_missing_image_reports_failure(tmp_path):
    assert install.unpack_install_image(
        str(tmp_path / "absent.7z"), str(tmp_path / "out")) is False


###########################################################
# Mount state
###########################################################

def test_an_empty_mount_directory_is_not_mounted(tmp_path):
    # An install image is unpacked rather than mounted, so content is the only
    # evidence it happened.
    mount = tmp_path / "mnt"
    mount.mkdir()

    assert install.is_install_image_mounted(str(tmp_path / "image.7z"), str(mount)) is False


def test_a_populated_mount_directory_is_mounted(tmp_path):
    mount = tmp_path / "mnt"
    mount.mkdir()
    (mount / "game.exe").write_text("content")

    assert install.is_install_image_mounted(str(tmp_path / "image.7z"), str(mount)) is True


def test_a_missing_mount_directory_is_not_mounted(tmp_path):
    assert install.is_install_image_mounted(
        str(tmp_path / "image.7z"), str(tmp_path / "absent")) is False
