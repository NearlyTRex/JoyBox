# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import nintendo
from nintendo_helpers import WAD_CONTENT, build_wad


###########################################################
# Wii WADs
###########################################################

@pytest.fixture
def wad_file(tmp_path):
    return build_wad(tmp_path / "channel.wad")


@pytest.fixture
def nand_dir(tmp_path):
    return str(tmp_path / "User" / "Wii")


@pytest.fixture
def logged(monkeypatch):
    state = {"info": [], "errors": [], "quits": []}
    monkeypatch.setattr(nintendo.logger, "log_info", lambda message, **kwargs: state["info"].append(message))

    def log_error(message, quit_program = False, **kwargs):
        state["errors"].append(message)
        state["quits"].append(quit_program)

    monkeypatch.setattr(nintendo.logger, "log_error", log_error)
    return state


def test_installing_a_wad_writes_its_title_into_the_nand(wad_file, nand_dir):
    assert nintendo.install_wii_wad(wad_file, nand_dir) is True

    content_dir = os.path.join(nand_dir, "title", "00010001", "57414c45", "content")
    with open(os.path.join(content_dir, "00000000.app"), "rb") as handle:
        assert handle.read() == WAD_CONTENT
    assert os.path.isfile(os.path.join(content_dir, "title.tmd"))
    assert os.path.isfile(os.path.join(nand_dir, "ticket", "00010001", "57414c45.tik"))


def test_installing_a_wad_creates_a_missing_nand(wad_file, nand_dir):
    assert not os.path.exists(nand_dir)

    nintendo.install_wii_wad(wad_file, nand_dir)

    assert os.path.isdir(os.path.join(nand_dir, "shared1"))


def test_installing_a_wad_again_replaces_its_title(wad_file, nand_dir):
    nintendo.install_wii_wad(wad_file, nand_dir)

    assert nintendo.install_wii_wad(wad_file, nand_dir) is True
    content_dir = os.path.join(nand_dir, "title", "00010001", "57414c45", "content")
    assert sorted(os.listdir(content_dir)) == ["00000000.app", "title.tmd"]


def test_a_pretend_install_writes_nothing(wad_file, nand_dir, logged):
    assert nintendo.install_wii_wad(wad_file, nand_dir, verbose = True, pretend_run = True) is True

    assert not os.path.exists(nand_dir)
    assert logged["info"][-1] == "Installing %s into NAND %s" % (wad_file, nand_dir)


def test_a_pretend_install_still_rejects_a_bad_wad(tmp_path, nand_dir, logged):
    bad = tmp_path / "bad.wad"
    bad.write_bytes(b"not a wad")

    assert nintendo.install_wii_wad(str(bad), nand_dir, pretend_run = True) is False


@pytest.mark.parametrize("exit_on_failure", [False, True])
def test_a_file_that_is_not_a_wad_is_not_installed(tmp_path, nand_dir, logged, exit_on_failure):
    bad = tmp_path / "bad.wad"
    bad.write_bytes(b"not a wad")

    assert nintendo.install_wii_wad(str(bad), nand_dir, exit_on_failure = exit_on_failure) is False

    assert not os.path.exists(nand_dir)
    assert logged["errors"][0] == "Unable to load WAD %s" % bad
    assert logged["quits"] == [False, exit_on_failure]


def test_an_unreadable_wad_is_not_installed(tmp_path, nand_dir, logged):
    missing = str(tmp_path / "missing.wad")

    assert nintendo.install_wii_wad(missing, nand_dir) is False
    assert logged["errors"] == ["Unable to read WAD %s" % missing]
    assert not os.path.exists(nand_dir)


def test_a_nand_that_cannot_be_created_stops_the_install(wad_file, tmp_path, logged):
    blocker = tmp_path / "blocker"
    blocker.write_text("")

    assert nintendo.install_wii_wad(wad_file, str(blocker / "Wii")) is False
    assert not os.path.exists(blocker / "Wii")


@pytest.mark.parametrize("exit_on_failure", [False, True])
def test_a_failed_nand_install_is_reported(wad_file, nand_dir, logged, monkeypatch, exit_on_failure):
    import libWiiPy

    def refuse(self, title, skip_hash = False):
        raise OSError("disk full")

    monkeypatch.setattr(libWiiPy.nand.EmuNAND, "install_title", refuse)

    assert nintendo.install_wii_wad(wad_file, nand_dir, exit_on_failure = exit_on_failure) is False
    assert logged["errors"][0] == "Unable to install WAD %s" % wad_file
    assert logged["quits"] == [False, exit_on_failure]
