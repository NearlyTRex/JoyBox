# Imports
import os
import subprocess
import pytest

# Local imports
from joybox import programs, xbox

pytestmark = [pytest.mark.requires_tool("ExtractXIso"), pytest.mark.slow]


###########################################################
# Xbox disc image round trip
#
# Runs the real extract-xiso. It can build an xiso from an ordinary directory,
# so the extract and rewrite paths are exercised without a game disc.
###########################################################

@pytest.fixture
def payload(tmp_path):
    source = tmp_path / "payload"
    source.mkdir()
    (source / "default.xbe").write_bytes(os.urandom(4096))
    (source / "data.bin").write_bytes(os.urandom(20000))
    return source


@pytest.fixture
def built_iso(tmp_path, payload, requires_tool):
    # Building the fixture image is scaffolding, so it calls the tool directly
    # rather than going through a wrapper.
    tool = programs.get_tool_program("ExtractXIso")
    target = tmp_path / "game.iso"
    result = subprocess.run(
        [tool, "-c", str(payload), str(target)],
        cwd = str(tmp_path), capture_output = True)
    assert result.returncode == 0, result.stderr.decode()
    assert target.exists()
    return target


###########################################################
# Extracting
###########################################################

def test_an_xiso_extracts_its_files(tmp_path, built_iso):
    out = tmp_path / "out"

    assert xbox.extract_xbox_iso(str(built_iso), str(out)) is True
    names = {path.name for path in out.rglob("*") if path.is_file()}
    assert {"default.xbe", "data.bin"} <= names


def test_extracted_content_matches_the_payload(tmp_path, built_iso, payload):
    out = tmp_path / "out"
    xbox.extract_xbox_iso(str(built_iso), str(out))
    restored = [path for path in out.rglob("data.bin")][0]

    assert restored.read_bytes() == (payload / "data.bin").read_bytes()


def test_extracting_a_non_xiso_reports_failure(tmp_path, requires_tool):
    source = tmp_path / "notanimage.iso"
    source.write_text("this is not a disc image")

    assert xbox.extract_xbox_iso(str(source), str(tmp_path / "out")) is False


def test_extracting_a_missing_image_reports_failure(tmp_path, requires_tool):
    assert xbox.extract_xbox_iso(
        str(tmp_path / "absent.iso"), str(tmp_path / "out")) is False


def test_a_failed_extract_leaves_the_image_alone(tmp_path, requires_tool):
    source = tmp_path / "notanimage.iso"
    source.write_text("this is not a disc image")
    xbox.extract_xbox_iso(str(source), str(tmp_path / "out"), delete_original = True)

    assert source.exists()


def test_a_successful_extract_deletes_the_image_when_asked(tmp_path, built_iso):
    out = tmp_path / "out"

    assert xbox.extract_xbox_iso(str(built_iso), str(out), delete_original = True) is True
    assert not built_iso.exists()
    assert (out / "data.bin").exists()


def test_pretending_extracts_nothing(tmp_path, built_iso):
    out = tmp_path / "out"
    xbox.extract_xbox_iso(str(built_iso), str(out), pretend_run = True)

    assert not out.exists()


###########################################################
# Rewriting
###########################################################

def test_an_xiso_is_rewritten(tmp_path, built_iso):
    assert xbox.rewrite_xbox_iso(str(built_iso)) is True
    assert built_iso.exists()


def test_a_rewritten_xiso_still_extracts(tmp_path, built_iso, payload):
    # An optimised image that no longer reads back would lose the game.
    xbox.rewrite_xbox_iso(str(built_iso))

    out = tmp_path / "out"
    assert xbox.extract_xbox_iso(str(built_iso), str(out)) is True
    restored = [path for path in out.rglob("data.bin")][0]
    assert restored.read_bytes() == (payload / "data.bin").read_bytes()


def test_rewriting_an_optimised_image_is_a_no_op(tmp_path, built_iso):
    # extract-xiso skips an image that is already optimised, which must read as
    # success rather than as a failed rewrite.
    original = built_iso.read_bytes()

    assert xbox.rewrite_xbox_iso(str(built_iso)) is True
    assert built_iso.read_bytes() == original


def test_rewriting_twice_is_stable(tmp_path, built_iso):
    xbox.rewrite_xbox_iso(str(built_iso))
    after_first = built_iso.read_bytes()
    xbox.rewrite_xbox_iso(str(built_iso))

    assert built_iso.read_bytes() == after_first


def test_discarding_the_original_leaves_the_image_in_place(tmp_path, built_iso):
    assert xbox.rewrite_xbox_iso(str(built_iso), delete_original = True) is True
    assert built_iso.exists()
    assert not [path for path in tmp_path.iterdir() if path.suffix == ".old"]


def test_rewriting_a_non_xiso_reports_failure(tmp_path, requires_tool):
    source = tmp_path / "notanimage.iso"
    source.write_text("this is not a disc image")

    assert xbox.rewrite_xbox_iso(str(source)) is False


def test_rewriting_a_missing_image_reports_failure(tmp_path, requires_tool):
    assert xbox.rewrite_xbox_iso(str(tmp_path / "absent.iso")) is False
