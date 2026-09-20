# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, cryption, hashutil


###########################################################
# Encrypted naming
#
# The encrypted name is what lands on the remote locker, so it has to be
# derived only from the original filename - a path-dependent name would change
# when the same file is synced from a different directory.
###########################################################

@pytest.mark.parametrize("extension", config.EncryptedFileType.cvalues())
def test_an_encrypted_extension_is_recognised(extension):
    assert cryption.is_file_encrypted(f"game{extension}") is True


def test_a_plain_file_is_not_encrypted():
    assert cryption.is_file_encrypted("game.iso") is False
    assert cryption.is_file_encrypted("game") is False


def test_an_encrypted_name_is_the_hash_of_the_filename():
    expected = hashutil.calculate_string_md5("game.iso") + config.EncryptedFileType.ENC.cval()

    assert cryption.generate_encrypted_filename("game.iso") == expected


def test_an_encrypted_name_is_deterministic():
    assert cryption.generate_encrypted_filename("game.iso") == \
        cryption.generate_encrypted_filename("game.iso")


def test_different_files_get_different_names():
    assert cryption.generate_encrypted_filename("one.iso") != \
        cryption.generate_encrypted_filename("two.iso")


def test_an_already_encrypted_name_passes_through():
    # Re-encrypting must not hash the hash.
    assert cryption.generate_encrypted_filename("abc123.enc") == "abc123.enc"


def test_an_encrypted_name_carries_the_encrypted_extension():
    assert cryption.generate_encrypted_filename("game.iso").endswith(
        config.EncryptedFileType.ENC.cval())


def test_an_encrypted_name_hides_the_original():
    assert "game" not in cryption.generate_encrypted_filename("game.iso")


###########################################################
# Encrypted paths
###########################################################

def test_an_encrypted_path_keeps_the_directory():
    assert cryption.generate_encrypted_path("a/b/game.iso").startswith("a/b/")


def test_an_encrypted_path_hashes_only_the_filename():
    # The same file in two directories has to encrypt to the same name, or a
    # move would look like a different file to the locker.
    first = cryption.generate_encrypted_path("a/game.iso")
    second = cryption.generate_encrypted_path("b/c/game.iso")

    assert first.split("/")[-1] == second.split("/")[-1]


def test_an_encrypted_path_for_a_bare_filename_has_no_directory():
    assert "/" not in cryption.generate_encrypted_path("game.iso")


###########################################################
# Passphrases
###########################################################

def test_a_non_empty_string_is_a_valid_passphrase():
    assert cryption.is_passphrase_valid("hunter2") is True


@pytest.mark.parametrize("candidate", ["", None, 123, [], b"bytes"])
def test_anything_else_is_not_a_valid_passphrase(candidate):
    assert cryption.is_passphrase_valid(candidate) is False


PASSPHRASE = "example"


###########################################################
# gpg invocations
#
# The stored file is only readable by a gpg run with the same options, so the
# cipher and the embedded name are part of the format rather than details.
###########################################################

@pytest.fixture
def gpg(monkeypatch):
    monkeypatch.setattr(cryption.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(cryption.programs, "get_tool_program", lambda name: "/tools/gpg")
    return "/tools/gpg"


@pytest.fixture
def no_gpg(monkeypatch):
    monkeypatch.setattr(cryption.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(cryption.programs, "get_tool_program", lambda name: None)


@pytest.fixture
def plain_source(tmp_path):
    source = tmp_path / "Save Game.dat"
    source.write_bytes(b"data")
    return str(source)


@pytest.fixture
def stored_source(tmp_path):
    source = tmp_path / "stored.enc"
    source.write_bytes(b"data")
    return str(source)


def encrypt(source, tmp_path, **kwargs):
    return cryption.encrypt_file(
        src = source, passphrase = PASSPHRASE,
        output_file = str(tmp_path / "out.enc"), **kwargs)


def decrypt(source, tmp_path, **kwargs):
    return cryption.decrypt_file(
        src = source, passphrase = PASSPHRASE,
        output_file = str(tmp_path / "out.dat"), **kwargs)


def test_encryption_uses_a_strong_cipher(gpg, recording_command, plain_source, tmp_path):
    encrypt(plain_source, tmp_path)

    assert recording_command.value_after("--cipher-algo") == "AES256"


def test_encryption_is_symmetric(gpg, recording_command, plain_source, tmp_path):
    # There are no keys in the collection; everything is passphrase based.
    encrypt(plain_source, tmp_path)

    assert "--symmetric" in recording_command.only()


def test_encryption_records_the_original_filename(gpg, recording_command, plain_source, tmp_path):
    # The stored name is a hash, so this is the only copy of the real name.
    encrypt(plain_source, tmp_path)

    assert recording_command.value_after("--set-filename") == "Save Game.dat"


def test_encryption_does_not_compress(gpg, recording_command, plain_source, tmp_path):
    # Game data is already compressed, and compressing first leaks size
    # information about the contents.
    encrypt(plain_source, tmp_path)

    assert recording_command.value_after("--compress-algo") == "none"


def test_encryption_never_prompts(gpg, recording_command, plain_source, tmp_path):
    # A prompt in a batch run hangs the whole backup.
    encrypt(plain_source, tmp_path)

    assert "--batch" in recording_command.only()


def test_encryption_writes_where_it_was_told(gpg, recording_command, plain_source, tmp_path):
    encrypt(plain_source, tmp_path)

    assert recording_command.value_after("--output") == str(tmp_path / "out.enc")
    assert recording_command.only()[-1] == plain_source


def test_decryption_names_its_output(gpg, recording_command, stored_source, tmp_path):
    decrypt(stored_source, tmp_path)

    assert recording_command.value_after("--output") == str(tmp_path / "out.dat")


def test_decryption_reads_the_stored_file(gpg, recording_command, stored_source, tmp_path):
    decrypt(stored_source, tmp_path)
    cmd = recording_command.only()

    assert "--decrypt" in cmd
    assert cmd[-1] == stored_source


def test_a_plain_source_is_copied_rather_than_decrypted(gpg, recording_command, plain_source, tmp_path):
    # Not everything in a locker is encrypted, and running gpg over a plain
    # file would fail rather than copy it.
    assert decrypt(plain_source, tmp_path) is True
    assert recording_command.ran() is False


def test_an_encrypted_source_is_copied_rather_than_re_encrypted(gpg, recording_command, stored_source, tmp_path):
    assert encrypt(stored_source, tmp_path) is True
    assert recording_command.ran() is False


def test_an_existing_destination_is_not_rewritten(gpg, recording_command, plain_source, tmp_path):
    (tmp_path / "out.enc").write_bytes(b"already here")

    assert encrypt(plain_source, tmp_path) is True
    assert recording_command.ran() is False


def test_reading_the_embedded_name_lists_packets(gpg, monkeypatch):
    from fakes import RecordingCommand
    recorder = RecordingCommand(
        monkeypatch,
        output = ':literal data packet:\n\tmode b, created 0, name="Save.dat",\n')

    assert cryption.get_embedded_filename(
        src = "/in/stored.enc", passphrase = PASSPHRASE) == "Save.dat"
    assert "--list-packets" in recorder.only()


def test_an_unreadable_packet_listing_yields_no_name(gpg, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = "gpg: decryption failed: Bad session key")

    assert cryption.get_embedded_filename(src = "/in/stored.enc", passphrase = PASSPHRASE) is None


def test_byte_output_is_decoded_for_a_packet_listing(gpg, monkeypatch):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, output = b'\tmode b, created 0, name="Save.dat",\n')

    assert cryption.get_embedded_filename(
        src = "/in/stored.enc", passphrase = PASSPHRASE) == "Save.dat"


def test_encrypting_without_gpg_reports_failure(no_gpg, recording_command, plain_source, tmp_path):
    assert encrypt(plain_source, tmp_path) is False
    assert recording_command.ran() is False


def test_decrypting_without_gpg_reports_failure(no_gpg, recording_command, stored_source, tmp_path):
    assert decrypt(stored_source, tmp_path) is False
    assert recording_command.ran() is False


def test_a_missing_gpg_yields_no_embedded_name(no_gpg, recording_command):
    assert cryption.get_embedded_filename(src = "/in/stored.enc", passphrase = PASSPHRASE) is None
    assert recording_command.ran() is False


def test_a_failed_encryption_reports_failure(gpg, monkeypatch, plain_source, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 2)

    assert encrypt(plain_source, tmp_path) is False


def test_a_failed_decryption_reports_failure(gpg, monkeypatch, stored_source, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 2)

    assert decrypt(stored_source, tmp_path) is False


def test_an_empty_passphrase_is_refused_for_encryption(gpg, plain_source, tmp_path):
    # An empty passphrase encrypts to something anyone can open.
    with pytest.raises(AssertionError):
        cryption.encrypt_file(
            src = plain_source, passphrase = "",
            output_file = str(tmp_path / "out.enc"))


def test_an_empty_passphrase_is_refused_for_decryption(gpg, stored_source, tmp_path):
    with pytest.raises(AssertionError):
        cryption.decrypt_file(
            src = stored_source, passphrase = "",
            output_file = str(tmp_path / "out.dat"))


###########################################################
# Resolving stored names without gpg
###########################################################

@pytest.fixture
def embedded_names(monkeypatch):
    names = {}
    monkeypatch.setattr(
        cryption, "get_embedded_filename",
        lambda src, **kwargs: names.get(os.path.basename(src)))
    return names


def test_a_stored_file_resolves_to_its_embedded_name(embedded_names):
    embedded_names["abc.enc"] = "Save Game.dat"

    assert cryption.get_real_file_path("/locker/abc.enc", "phrase") == \
        os.path.join("/locker", "Save Game.dat")


def test_a_stored_file_without_a_readable_name_resolves_to_nothing(embedded_names):
    assert cryption.get_real_file_path("/locker/abc.enc", "phrase") is None


def test_only_the_readable_names_are_resolved(embedded_names):
    # One unreadable file in a locker should not cost the rest of the listing.
    embedded_names["first.enc"] = "First.dat"

    resolved = cryption.get_real_file_paths(
        ["/locker/first.enc", "/locker/second.enc"], "phrase")

    assert resolved == [os.path.join("/locker", "First.dat")]


def test_something_that_is_not_a_list_resolves_to_nothing(embedded_names):
    assert cryption.get_real_file_paths("/locker/first.enc", "phrase") == []
