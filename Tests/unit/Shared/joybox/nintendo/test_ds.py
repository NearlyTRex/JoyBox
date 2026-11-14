# Third-party imports
import pytest

# Local imports
from joybox.nintendo import ds


###########################################################
# Nintendo DS
###########################################################

def test_encrypting_a_ds_rom_uses_the_encrypt_mode(installed, recording_command):
    ds.encrypt_nds_rom("/in/Game.nds")

    assert recording_command.only() == ["/tools/ndecrypt", "e", "/in/Game.nds"]


def test_decrypting_a_ds_rom_uses_the_decrypt_mode(installed, recording_command):
    ds.decrypt_nds_rom("/in/Game.nds")

    assert recording_command.only() == ["/tools/ndecrypt", "d", "/in/Game.nds"]


@pytest.mark.parametrize("wrapper", [ds.encrypt_nds_rom, ds.decrypt_nds_rom])
def test_a_ds_hash_is_only_generated_when_asked(installed, recording_command, wrapper):
    wrapper("/in/Game.nds", generate_hash = True)

    assert "-h" in recording_command.only()


@pytest.mark.parametrize("wrapper", [ds.encrypt_nds_rom, ds.decrypt_nds_rom])
def test_the_rom_stays_last_after_the_hash_flag(installed, recording_command, wrapper):
    # NDecrypt takes the rom as a positional; a flag appended after it is read
    # as a second file.
    wrapper("/in/Game.nds", generate_hash = True)

    assert recording_command.only()[-1] == "/in/Game.nds"


@pytest.mark.parametrize("wrapper", [ds.encrypt_nds_rom, ds.decrypt_nds_rom])
def test_a_ds_wrapper_blocks_on_the_tool(installed, recording_command, wrapper):
    wrapper("/in/Game.nds")

    assert "/tools/ndecrypt" in recording_command.options().get_blocking_processes()


@pytest.mark.parametrize("wrapper", [ds.encrypt_nds_rom, ds.decrypt_nds_rom])
def test_a_ds_wrapper_without_its_tool_reports_failure(missing, recording_command, wrapper):
    assert wrapper("/in/Game.nds") is False
    assert recording_command.ran() is False


@pytest.mark.parametrize("wrapper", [ds.encrypt_nds_rom, ds.decrypt_nds_rom])
def test_a_failed_ds_wrapper_reports_failure(installed, monkeypatch, wrapper):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert wrapper("/in/Game.nds") is False
