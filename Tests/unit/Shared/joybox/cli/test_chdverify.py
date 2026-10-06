# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import chdverify


###########################################################
# chdverify
#
# Every .chd under the input is verified, and the first failure stops the run.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, chdverify)
    command.verify = Recorder(result = True)
    monkeypatch.setattr(chdverify.chd, "verify_disc_chd", command.verify)
    return command


@pytest.fixture
def discs(tmp_path):
    (tmp_path / "sub").mkdir()
    for name in ["a.chd", "sub/b.chd", "notes.txt"]:
        (tmp_path / name).write_bytes(b"")
    return tmp_path


def test_every_chd_is_verified(tool, discs):
    tool.main("-i", str(discs), "--no-preview")

    assert [call["_args"][0] for call in tool.verify.calls] == [str(discs / "a.chd"), str(discs / "sub" / "b.chd")]
    assert tool.infos.count("Verified!") == 2


def test_a_failed_verification_stops_the_run(tool, discs):
    tool.verify.result = False

    with pytest.raises(SystemExit):
        tool.main("-i", str(discs), "--no-preview")
    assert len(tool.verify.calls) == 1
    assert tool.errors == ["Verification failed!"]


def test_the_preview_names_the_path(tool, discs):
    tool.main("-i", str(discs))

    assert tool.previews == [("Verify CHD", ["Path: %s" % discs])]


def test_a_declined_preview_verifies_nothing(tool, discs):
    tool.confirm = False

    tool.main("-i", str(discs))

    assert tool.verify.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, chdverify)
