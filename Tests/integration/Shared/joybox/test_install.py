# Imports
import os
import pytest

# Local imports
from joybox import config, install

pytestmark = pytest.mark.slow


###########################################################
# Install images
#
# A snapshot of a Wine prefix after an installer has run, packed for the
# locker. The ignore list keeps the Windows layer out; a path that slips
# through adds hundreds of megabytes of system files per game.
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


def unpacked_names(root):
    return {
        os.path.relpath(os.path.join(current, name), str(root)).replace("\\", "/")
        for current, _, files in os.walk(str(root)) for name in files
    }


###########################################################
# Packing
###########################################################

def test_an_install_image_is_packed(tmp_path, prefix):
    image = tmp_path / "install.7z"

    assert install.pack_install_image(str(prefix), str(image)) is True
    assert image.exists()
    assert image.stat().st_size > 0


def test_a_packed_image_holds_the_game_files(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))

    out = tmp_path / "out"
    assert install.unpack_install_image(str(image), str(out)) is True
    assert "Program Files/Game/game.exe" in unpacked_names(out)


def test_nesting_survives_a_pack_and_unpack(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))

    out = tmp_path / "out"
    install.unpack_install_image(str(image), str(out))
    assert "Program Files/Game/data/assets.pak" in unpacked_names(out)


def test_file_contents_survive_a_round_trip(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))

    out = tmp_path / "out"
    install.unpack_install_image(str(image), str(out))
    restored = out / "Program Files" / "Game" / "game.exe"
    assert restored.read_text() == "content of Program Files/Game/game.exe\n"


def test_an_empty_directory_packs_nothing(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()
    image = tmp_path / "install.7z"

    assert install.pack_install_image(str(source), str(image)) is False
    assert not image.exists()


def test_a_missing_directory_packs_nothing(tmp_path):
    image = tmp_path / "install.7z"

    assert install.pack_install_image(str(tmp_path / "absent"), str(image)) is False


def test_the_source_is_kept_by_default(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))

    assert prefix.exists()


def test_the_source_is_removed_when_asked(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image), delete_original = True)

    assert not prefix.exists()
    assert image.exists()


def test_pretending_packs_nothing(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image), pretend_run = True)

    assert not image.exists()


###########################################################
# Ignored paths
#
# Everything the Windows layer leaves behind, plus the user's own profile.
###########################################################

@pytest.mark.parametrize("ignored", config.ignored_paths_install)
def test_every_ignored_path_is_left_out(tmp_path, ignored):
    source = tmp_path / "prefix"
    source.mkdir()
    make_tree(source, "Program Files/Game/game.exe", "%s/junk.dat" % ignored)
    image = tmp_path / "install.7z"

    assert install.pack_install_image(str(source), str(image)) is True
    out = tmp_path / "out"
    install.unpack_install_image(str(image), str(out))
    packed = unpacked_names(out)

    assert "Program Files/Game/game.exe" in packed
    assert not any(name.startswith(ignored) for name in packed)


def test_a_prefix_of_only_ignored_paths_packs_nothing(tmp_path):
    source = tmp_path / "prefix"
    source.mkdir()
    make_tree(source, "windows/system32/kernel32.dll", "users/someone/file.txt")
    image = tmp_path / "install.7z"

    assert install.pack_install_image(str(source), str(image)) is False
    assert not image.exists()


def test_a_similarly_named_path_is_kept(tmp_path):
    # "windows" is ignored; a game folder starting with it is not the same
    # thing, though the check is a prefix match.
    source = tmp_path / "prefix"
    source.mkdir()
    make_tree(source, "Program Files/Game/game.exe", "windowsill/keep.dat")
    image = tmp_path / "install.7z"
    install.pack_install_image(str(source), str(image))

    out = tmp_path / "out"
    install.unpack_install_image(str(image), str(out))
    packed = unpacked_names(out)

    assert "Program Files/Game/game.exe" in packed


###########################################################
# Unpacking
###########################################################

def test_unpacking_creates_the_target(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))
    out = tmp_path / "nested" / "out"

    assert install.unpack_install_image(str(image), str(out)) is True
    assert out.exists()


def test_unpacking_a_missing_image_reports_failure(tmp_path):
    assert install.unpack_install_image(
        str(tmp_path / "absent.7z"), str(tmp_path / "out")) is False


def test_unpacking_a_non_archive_reports_failure(tmp_path):
    source = tmp_path / "notanarchive.7z"
    source.write_text("this is not an archive")

    assert install.unpack_install_image(str(source), str(tmp_path / "out")) is False


def test_the_image_is_kept_by_default(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))
    install.unpack_install_image(str(image), str(tmp_path / "out"))

    assert image.exists()


def test_the_image_is_removed_when_asked(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))
    install.unpack_install_image(
        str(image), str(tmp_path / "out"), delete_original = True)

    assert not image.exists()


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


def test_mounting_unpacks_into_an_empty_directory(tmp_path, prefix):
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))
    mount = tmp_path / "mnt"
    mount.mkdir()

    assert install.mount_install_image(str(image), str(mount)) is True
    assert "Program Files/Game/game.exe" in unpacked_names(mount)


def test_mounting_an_already_populated_directory_does_nothing(tmp_path, prefix):
    # Unpacking over an existing mount would overwrite a running game's files.
    image = tmp_path / "install.7z"
    install.pack_install_image(str(prefix), str(image))
    mount = tmp_path / "mnt"
    mount.mkdir()
    (mount / "existing.txt").write_text("already here")

    assert install.mount_install_image(str(image), str(mount)) is True
    assert unpacked_names(mount) == {"existing.txt"}
