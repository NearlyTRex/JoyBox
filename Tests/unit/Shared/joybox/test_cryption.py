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


@pytest.mark.parametrize("operation", [
    lambda plain, stored, tmp_path: encrypt(plain, tmp_path),
    lambda plain, stored, tmp_path: decrypt(stored, tmp_path),
    lambda plain, stored, tmp_path: cryption.get_embedded_filename(src = stored, passphrase = PASSPHRASE),
], ids = ["encrypt", "decrypt", "list-packets"])
def test_the_passphrase_goes_over_stdin_not_argv(gpg, recording_command, plain_source, stored_source, tmp_path, operation):
    # argv is visible to every local user and is what a verbose run logs.
    operation(plain_source, stored_source, tmp_path)

    assert PASSPHRASE not in recording_command.only()
    assert recording_command.value_after("--passphrase-fd") == "0"
    assert recording_command.options().get_stdin_input() == PASSPHRASE


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


def test_a_plain_file_is_its_own_real_path(embedded_names):
    assert cryption.get_real_file_path("/locker/Save.dat", "phrase") == "/locker/Save.dat"


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


###########################################################
# Argument checks before gpg
###########################################################

INVALID_PATH = "bad\0path"


def test_an_invalid_source_is_not_encrypted(gpg, recording_command, tmp_path):
    assert encrypt(INVALID_PATH, tmp_path) is False
    assert recording_command.ran() is False


def test_an_invalid_destination_is_not_encrypted(gpg, recording_command, plain_source):
    assert cryption.encrypt_file(
        src = plain_source, passphrase = PASSPHRASE, output_file = INVALID_PATH) is False
    assert recording_command.ran() is False


def test_encryption_defaults_to_the_hashed_name_beside_the_source(gpg, recording_command, plain_source):
    cryption.encrypt_file(src = plain_source, passphrase = PASSPHRASE)

    assert recording_command.value_after("--output") == cryption.generate_encrypted_path(plain_source)


def test_an_invalid_source_is_not_decrypted(gpg, recording_command, tmp_path):
    assert decrypt(INVALID_PATH, tmp_path) is False
    assert recording_command.ran() is False


def test_an_invalid_destination_is_not_decrypted(gpg, recording_command, stored_source):
    assert cryption.decrypt_file(
        src = stored_source, passphrase = PASSPHRASE, output_file = INVALID_PATH) is False
    assert recording_command.ran() is False


def test_an_existing_decryption_destination_is_not_rewritten(gpg, recording_command, stored_source, tmp_path):
    (tmp_path / "out.dat").write_bytes(b"already here")

    assert decrypt(stored_source, tmp_path) is True
    assert recording_command.ran() is False


def test_decryption_defaults_to_the_embedded_name_beside_the_source(gpg, monkeypatch, stored_source, tmp_path):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")
    from fakes import RecordingCommand
    recorder = RecordingCommand(monkeypatch)

    cryption.decrypt_file(src = stored_source, passphrase = PASSPHRASE)

    assert recorder.value_after("--output") == str(tmp_path / "Save.dat")


def test_decryption_without_a_readable_name_is_refused(gpg, monkeypatch, recording_command, stored_source):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: None)

    assert cryption.decrypt_file(src = stored_source, passphrase = PASSPHRASE) is False
    assert recording_command.ran() is False


###########################################################
# gpg results
###########################################################

class FakeGpg:

    # Writes the output gpg would have produced, so the result checks see a file.
    def __init__(self, monkeypatch, content = b"plain", write = True):
        self.calls = []
        self.content = content
        self.write = write
        monkeypatch.setattr(cryption.command, "run_returncode_command", self.run)

    def run(self, cmd, **kwargs):
        self.calls.append(cmd)
        if self.write:
            with open(cmd[cmd.index("--output") + 1], "wb") as handle:
                handle.write(self.content)
        return 0


@pytest.fixture
def removed(monkeypatch):
    removed = []
    monkeypatch.setattr(
        cryption.fileops, "remove_file", lambda src, **kwargs: removed.append(src))
    return removed


def test_a_pretend_encryption_succeeds_without_output(gpg, recording_command, plain_source, tmp_path):
    assert encrypt(plain_source, tmp_path, pretend_run = True) is True
    assert not (tmp_path / "out.enc").exists()


def test_a_pretend_decryption_succeeds_without_output(gpg, recording_command, stored_source, tmp_path):
    assert decrypt(stored_source, tmp_path, pretend_run = True) is True
    assert not (tmp_path / "out.dat").exists()


def test_an_encryption_succeeds_when_gpg_writes_the_output(gpg, monkeypatch, plain_source, tmp_path):
    FakeGpg(monkeypatch)

    assert encrypt(plain_source, tmp_path) is True


def test_an_encryption_that_writes_nothing_fails(gpg, monkeypatch, plain_source, tmp_path):
    FakeGpg(monkeypatch, write = False)

    assert encrypt(plain_source, tmp_path) is False


def test_an_encryption_can_remove_the_original(gpg, monkeypatch, removed, plain_source, tmp_path):
    FakeGpg(monkeypatch)

    assert encrypt(plain_source, tmp_path, delete_original = True) is True
    assert removed == [plain_source]


def test_a_failed_encryption_keeps_the_original(gpg, monkeypatch, removed, plain_source, tmp_path):
    FakeGpg(monkeypatch, write = False)

    encrypt(plain_source, tmp_path, delete_original = True)

    assert removed == []


def test_a_decryption_can_remove_the_original(gpg, monkeypatch, removed, stored_source, tmp_path):
    FakeGpg(monkeypatch)

    assert decrypt(stored_source, tmp_path, delete_original = True) is True
    assert removed == [stored_source]


def test_a_decryption_keeps_the_original_by_default(gpg, monkeypatch, removed, stored_source, tmp_path):
    FakeGpg(monkeypatch)

    assert decrypt(stored_source, tmp_path) is True
    assert removed == []


###########################################################
# Embedded file info
###########################################################

@pytest.fixture
def scratch(monkeypatch, tmp_path):
    # Stands in for the temporary directory the decrypted copy is staged in.
    state = {"dir": tmp_path / "scratch", "made": True, "removed": []}
    state["dir"].mkdir()
    monkeypatch.setattr(
        cryption.fileops, "create_temporary_directory",
        lambda **kwargs: (state["made"], str(state["dir"])))
    monkeypatch.setattr(
        cryption.fileops, "remove_directory",
        lambda src, **kwargs: state["removed"].append(src))
    return state


def fake_hasher(src, **kwargs):
    with open(src, "rb") as handle:
        return "hash:" + handle.read().decode()


def embedded_info(source, **kwargs):
    return cryption.get_embedded_file_info(
        src = source, passphrase = PASSPHRASE, hasher = fake_hasher, **kwargs)


def test_embedded_info_describes_the_decrypted_copy(gpg, monkeypatch, scratch, stored_source):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")
    FakeGpg(monkeypatch, content = b"twelve bytes")

    info = embedded_info(stored_source)

    assert info["filename"] == "Save.dat"
    assert info["hash"] == "hash:twelve bytes"
    assert info["size"] == 12
    assert info["mtime"] == int(os.path.getmtime(stored_source))


def test_embedded_info_stages_the_copy_under_its_real_name(gpg, monkeypatch, scratch, stored_source):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")
    fake = FakeGpg(monkeypatch)

    embedded_info(stored_source)

    assert fake.calls[0][fake.calls[0].index("--output") + 1] == str(scratch["dir"] / "Save.dat")


def test_embedded_info_cleans_up_the_decrypted_copy(gpg, monkeypatch, scratch, stored_source):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")
    FakeGpg(monkeypatch)

    embedded_info(stored_source)

    assert scratch["removed"] == [str(scratch["dir"])]


def test_embedded_info_without_a_hasher_has_no_hash(gpg, monkeypatch, scratch, stored_source):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")
    FakeGpg(monkeypatch)

    info = cryption.get_embedded_file_info(src = stored_source, passphrase = PASSPHRASE, hasher = None)

    assert "hash" not in info
    assert info["size"] == len(b"plain")


def test_embedded_info_needs_a_readable_name(gpg, monkeypatch, scratch, stored_source):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: None)

    assert embedded_info(stored_source) is None


def test_embedded_info_needs_a_scratch_directory(gpg, monkeypatch, scratch, stored_source):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")
    scratch["made"] = False
    fake = FakeGpg(monkeypatch)

    assert embedded_info(stored_source) is None
    assert fake.calls == []


def test_a_failed_decrypt_yields_no_info_and_cleans_up(gpg, monkeypatch, scratch, stored_source):
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 2)

    assert embedded_info(stored_source) is None
    assert scratch["removed"] == [str(scratch["dir"])]


def test_a_pretend_run_reports_info_without_a_decrypted_copy(gpg, monkeypatch, scratch, stored_source):
    # A pretend decrypt writes nothing, so there is nothing to measure.
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch)

    info = cryption.get_embedded_file_info(
        src = stored_source, passphrase = PASSPHRASE, hasher = None, pretend_run = True)

    assert info["filename"] == "Save.dat"
    assert info["size"] == 0


###########################################################
# Whole trees
###########################################################

def test_every_file_in_a_tree_is_encrypted_beside_itself(gpg, monkeypatch, tmp_path):
    FakeGpg(monkeypatch)
    (tmp_path / "a.dat").write_bytes(b"a")
    (tmp_path / "b.dat").write_bytes(b"b")

    outputs = cryption.encrypt_files(str(tmp_path), PASSPHRASE)

    assert sorted(outputs) == sorted(
        cryption.generate_encrypted_path(str(tmp_path / name)) for name in ["a.dat", "b.dat"])


def test_a_file_that_fails_to_encrypt_is_left_out(gpg, recording_command, tmp_path):
    (tmp_path / "a.dat").write_bytes(b"a")

    assert cryption.encrypt_files(str(tmp_path), PASSPHRASE) == []


def test_every_file_in_a_tree_is_decrypted_to_its_real_name(gpg, monkeypatch, tmp_path):
    FakeGpg(monkeypatch)
    (tmp_path / "abc.enc").write_bytes(b"a")
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")

    assert cryption.decrypt_files(str(tmp_path), PASSPHRASE) == [str(tmp_path / "Save.dat")]


def test_a_file_without_a_readable_name_is_skipped(gpg, monkeypatch, tmp_path):
    # Its name is asked for once; decrypt_file would otherwise ask gpg again.
    asked = []
    (tmp_path / "abc.enc").write_bytes(b"a")
    monkeypatch.setattr(
        cryption, "get_embedded_filename", lambda src, **kwargs: asked.append(src))
    fake = FakeGpg(monkeypatch)

    assert cryption.decrypt_files(str(tmp_path), PASSPHRASE) == []
    assert asked == [str(tmp_path / "abc.enc")]
    assert fake.calls == []


def test_a_file_that_fails_to_decrypt_is_left_out(gpg, monkeypatch, recording_command, tmp_path):
    (tmp_path / "abc.enc").write_bytes(b"a")
    monkeypatch.setattr(cryption, "get_embedded_filename", lambda src, **kwargs: "Save.dat")

    assert cryption.decrypt_files(str(tmp_path), PASSPHRASE) == []
