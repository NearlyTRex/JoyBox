# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import verify_archives


###########################################################
# Verification
#
# The first archive that fails its test stops the run with an error.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, verify_archives)
    harness.tested = []
    harness.bad = set()
    for name in ("a.zip", "b.zip", "c.7z"):
        (tmp_path / name).write_bytes(b"")

    def test_archive(archive_file, **kwargs):
        harness.tested.append(archive_file.rsplit("/", 1)[-1])
        return harness.tested[-1] not in harness.bad

    monkeypatch.setattr(verify_archives.archive, "test_archive", test_archive)
    return harness


def test_every_archive_of_the_chosen_types_is_tested(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-a", "ZIP", "7Z")

    assert sorted(tool.tested) == ["a.zip", "b.zip", "c.7z"]


def test_a_failed_archive_stops_the_run(tool, tmp_path):
    tool.bad = {"a.zip", "b.zip"}

    assert tool.exit_code("--no-preview", "-i", str(tmp_path)) != 0

    assert len(tool.tested) == 1
    assert tool.errors == ["Verification failed!"]


def test_the_preview_lists_the_types(tool, tmp_path):
    tool.run("-i", str(tmp_path))

    assert tool.previews == [("Verify archives", ["Path: %s" % tmp_path, "Archive types: ['.zip']"])]


def test_a_cancelled_preview_tests_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path))

    assert tool.tested == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, verify_archives)
