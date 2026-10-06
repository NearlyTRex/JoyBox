# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import crypt_tool


###########################################################
# Passphrase and direction
#
# The passphrase type picks which configured secret is used; with none set
# nothing is touched.
###########################################################

GENERAL_PHRASE = "general-test-phrase"
LOCKER_PHRASE = "locker-test-phrase"


@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, crypt_tool)
    harness.encrypted = []
    harness.decrypted = []
    isolated_settings.set_value("UserData.Protection", "general_passphrase", GENERAL_PHRASE)
    isolated_settings.set_value("UserData.Protection", "locker_passphrase", LOCKER_PHRASE)
    monkeypatch.setattr(crypt_tool.cryption, "encrypt_file", lambda **kwargs: harness.encrypted.append(kwargs))
    monkeypatch.setattr(crypt_tool.cryption, "decrypt_file", lambda **kwargs: harness.decrypted.append(kwargs))
    data = tmp_path / "data"
    data.mkdir()
    (data / "a.txt").write_text("a")
    (data / "b.txt").write_text("b")
    harness.data = data
    return harness


def test_encryption_uses_the_general_passphrase_and_deletes_originals(tool):
    tool.run("--no-preview", "-i", str(tool.data), "-t", "General", "-e")

    assert sorted(call["src"].rsplit("/", 1)[-1] for call in tool.encrypted) == ["a.txt", "b.txt"]
    assert {call["passphrase"] for call in tool.encrypted} == {GENERAL_PHRASE}
    assert all(call["delete_original"] for call in tool.encrypted)
    assert tool.decrypted == []


def test_decryption_uses_the_locker_passphrase_and_can_keep_originals(tool):
    tool.run("--no-preview", "-i", str(tool.data), "-t", "Locker", "-d", "-k")

    assert len(tool.decrypted) == 2
    assert {call["passphrase"] for call in tool.decrypted} == {LOCKER_PHRASE}
    assert not any(call["delete_original"] for call in tool.decrypted)
    assert tool.encrypted == []


def test_without_a_passphrase_nothing_is_processed(tool):
    assert tool.exit_code("--no-preview", "-i", str(tool.data), "-e") != 0

    assert tool.errors == ["No passphrase set"]
    assert tool.encrypted == []


@pytest.mark.parametrize("flags, action", [(["-e"], "Encrypt"), (["-d"], "Decrypt"), ([], "Unknown")])
def test_the_preview_names_the_direction(tool, flags, action):
    tool.run("-i", str(tool.data), "-t", "General", *flags)

    assert tool.previews[0][0] == "%s files" % action


def test_without_a_direction_nothing_is_processed(tool):
    tool.run("--no-preview", "-i", str(tool.data), "-t", "General")

    assert tool.encrypted == tool.decrypted == []


def test_a_cancelled_preview_processes_nothing(tool):
    tool.confirm = False

    tool.run("-i", str(tool.data), "-t", "General", "-e")

    assert tool.encrypted == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, crypt_tool)
