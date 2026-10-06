# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import nintendo


###########################################################
# Wii U packages
###########################################################

def test_decrypting_a_package_passes_its_title_files(installed, recording_command, nus_package):
    nintendo.decrypt_wiiu_nus_package(nus_package)

    assert recording_command.only() == [
        "/tools/cdecrypt",
        os.path.join(nus_package, "title.tmd"),
        os.path.join(nus_package, "title.tik"),
    ]


def test_decrypting_a_package_runs_inside_it(installed, recording_command, nus_package):
    # CDecrypt writes its output into the working directory.
    nintendo.decrypt_wiiu_nus_package(nus_package)

    assert recording_command.options().get_cwd() == nus_package


@pytest.mark.parametrize("absent", ["title.tmd", "title.tik"])
def test_a_package_missing_a_title_file_is_not_decrypted(installed, recording_command, nus_package, absent):
    os.remove(os.path.join(nus_package, absent))

    assert nintendo.decrypt_wiiu_nus_package(nus_package) is False
    assert recording_command.ran() is False


def test_decrypting_a_package_without_its_tool_reports_failure(missing, recording_command, nus_package):
    assert nintendo.decrypt_wiiu_nus_package(nus_package) is False
    assert recording_command.ran() is False


def test_a_failed_package_decrypt_reports_failure(installed, monkeypatch, nus_package):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    assert nintendo.decrypt_wiiu_nus_package(nus_package) is False


def test_decrypting_removes_only_the_encrypted_sources(installed, recording_command, nus_package):
    # The decrypted output shares the directory, so the cleanup is by
    # extension and must leave anything else alone.
    assert nintendo.decrypt_wiiu_nus_package(nus_package, delete_original = True) is True
    assert sorted(os.listdir(nus_package)) == ["keep.txt"]


def test_a_failed_decrypt_removes_nothing(installed, monkeypatch, nus_package):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)

    nintendo.decrypt_wiiu_nus_package(nus_package, delete_original = True)

    assert "title.tmd" in os.listdir(nus_package)


def test_verifying_a_package_works_on_a_copy(installed, recording_command, nus_package, scratch, monkeypatch):
    # Decryption writes into the package directory, so verifying in place
    # would modify the very thing it was asked to check.
    seen = {}
    monkeypatch.setattr(nintendo.fileops, "copy_contents", lambda src, dest, **kwargs: True)
    def decrypt_wiiu_nus_package(nus_package_dir, **kwargs):
        seen["dir"] = nus_package_dir
        return True

    monkeypatch.setattr(nintendo, "decrypt_wiiu_nus_package", decrypt_wiiu_nus_package)

    nintendo.verify_wiiu_nus_package(nus_package)

    assert seen["dir"] == scratch


def test_verifying_a_package_copies_it_to_the_scratch_directory(installed, recording_command, nus_package, scratch, monkeypatch):
    copies = []
    monkeypatch.setattr(
        nintendo.fileops, "copy_contents",
        lambda src, dest, **kwargs: copies.append((src, dest)))
    monkeypatch.setattr(nintendo, "decrypt_wiiu_nus_package", lambda **kwargs: True)

    nintendo.verify_wiiu_nus_package(nus_package)

    assert copies == [(nus_package, scratch)]


def test_a_package_that_will_not_decrypt_is_not_verified(installed, nus_package, scratch, monkeypatch):
    monkeypatch.setattr(nintendo.fileops, "copy_contents", lambda **kwargs: True)
    monkeypatch.setattr(nintendo, "decrypt_wiiu_nus_package", lambda **kwargs: False)

    assert nintendo.verify_wiiu_nus_package(nus_package) is False


def test_verifying_without_a_scratch_directory_reports_failure(installed, nus_package, no_scratch):
    assert nintendo.verify_wiiu_nus_package(nus_package) is False


###########################################################
# Wii U keys
###########################################################

def test_new_keys_are_added_to_the_existing_ones(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("aaa\nbbb\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("ccc\n")

    assert nintendo.update_wiiu_keys(str(incoming), str(existing)) is True

    assert existing.read_text().split() == ["aaa", "bbb", "ccc"]


def test_a_key_already_present_is_not_duplicated(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("aaa\nbbb\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("bbb\nccc\n")

    assert nintendo.update_wiiu_keys(str(incoming), str(existing)) is True

    assert existing.read_text().split() == ["aaa", "bbb", "ccc"]


def test_keys_are_written_in_a_stable_order(tmp_path):
    # An unsorted rewrite makes every update look like a change in git.
    existing = tmp_path / "keys.txt"
    existing.write_text("ccc\naaa\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("bbb\n")

    assert nintendo.update_wiiu_keys(str(incoming), str(existing)) is True

    assert existing.read_text().split() == ["aaa", "bbb", "ccc"]


def test_surrounding_whitespace_is_stripped_from_keys(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("  aaa  \n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("\taaa\n")

    assert nintendo.update_wiiu_keys(str(incoming), str(existing)) is True

    assert existing.read_text().split() == ["aaa"]


def test_the_source_key_file_is_left_alone(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("aaa\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("bbb\n")

    assert nintendo.update_wiiu_keys(str(incoming), str(existing)) is True

    assert incoming.read_text() == "bbb\n"


def test_keys_merge_without_a_trailing_newline_or_blank_lines(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("aaa\n\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("bbb")

    assert nintendo.update_wiiu_keys(str(incoming), str(existing)) is True
    assert existing.read_text() == "aaa\nbbb\n"


def test_a_pretend_key_update_writes_nothing(tmp_path):
    existing = tmp_path / "keys.txt"
    existing.write_text("aaa\n")
    incoming = tmp_path / "new.txt"
    incoming.write_text("bbb\n")

    assert nintendo.update_wiiu_keys(str(incoming), str(existing), pretend_run = True) is True
    assert existing.read_text() == "aaa\n"


@pytest.mark.parametrize("missing", ["src", "dest"])
def test_a_missing_key_file_fails_the_update(tmp_path, monkeypatch, missing):
    errors = []
    monkeypatch.setattr(nintendo.logger, "log_error", lambda message, **kwargs: errors.append(message))
    files = {"src": tmp_path / "new.txt", "dest": tmp_path / "keys.txt"}
    for name, path in files.items():
        if name != missing:
            path.write_text("aaa\n")

    assert nintendo.update_wiiu_keys(str(files["src"]), str(files["dest"])) is False
    assert errors == ["Unable to read Wii U keys file %s" % files[missing]]
    assert not files[missing].exists()


def test_decrypting_leaves_subdirectories_alone(installed, recording_command, nus_package):
    os.mkdir(os.path.join(nus_package, "code"))

    assert nintendo.decrypt_wiiu_nus_package(nus_package, delete_original = True) is True
    assert sorted(os.listdir(nus_package)) == ["code", "keep.txt"]


###########################################################
# Wii U installation
###########################################################

APP_XML = '<?xml version="1.0"?><app><title_id type="hexBinary" length="8">0005000010101A00</title_id></app>'


@pytest.fixture
def decrypted(monkeypatch):
    # Decryption is faked as writing the folders cdecrypt produces.
    state = {"ok": True, "app_xml": APP_XML, "dirs": []}

    def decrypt_wiiu_nus_package(nus_package_dir, **kwargs):
        state["dirs"].append(nus_package_dir)
        if not state["ok"]:
            return False
        for folder in ["code", "content", "meta"]:
            os.makedirs(os.path.join(nus_package_dir, folder), exist_ok = True)
        if state["app_xml"] is not None:
            with open(os.path.join(nus_package_dir, "code", "app.xml"), "w") as handle:
                handle.write(state["app_xml"])
        return True
    monkeypatch.setattr(nintendo, "decrypt_wiiu_nus_package", decrypt_wiiu_nus_package)
    return state


def test_a_package_is_installed_under_its_title_id(nus_package, scratch, decrypted, tmp_path):
    nand = tmp_path / "nand"

    assert nintendo.install_wiiu_nus_package(nus_package, str(nand)) is True

    title_dir = nand / "usr" / "title" / "00050000" / "10101a00"
    assert sorted(os.listdir(title_dir)) == ["code", "content", "meta"]
    assert (title_dir / "code" / "app.xml").exists()
    assert decrypted["dirs"] == [scratch]
    assert not os.path.exists(scratch)
    assert "title.tmd" in os.listdir(nus_package)


def test_installing_needs_a_scratch_directory(nus_package, no_scratch, decrypted, tmp_path):
    assert nintendo.install_wiiu_nus_package(nus_package, str(tmp_path / "nand")) is False
    assert decrypted["dirs"] == []


def test_an_empty_package_is_not_installed(scratch, decrypted, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    assert nintendo.install_wiiu_nus_package(str(empty), str(tmp_path / "nand")) is False
    assert decrypted["dirs"] == []


def test_a_package_that_will_not_decrypt_is_not_installed(nus_package, scratch, decrypted, tmp_path):
    decrypted["ok"] = False

    assert nintendo.install_wiiu_nus_package(nus_package, str(tmp_path / "nand")) is False


@pytest.mark.parametrize("app_xml", [None, "", "<app><title_id>00050000</title_id></app>"])
def test_a_package_without_a_usable_title_id_is_not_installed(nus_package, scratch, decrypted, tmp_path, app_xml):
    decrypted["app_xml"] = app_xml

    assert nintendo.install_wiiu_nus_package(nus_package, str(tmp_path / "nand")) is False
    assert not (tmp_path / "nand").exists()


def test_an_unparseable_app_xml_is_not_installed(nus_package, scratch, decrypted, monkeypatch, tmp_path):
    monkeypatch.setattr(nintendo.webpage, "parse_xml_page_source", lambda data: None)

    assert nintendo.install_wiiu_nus_package(nus_package, str(tmp_path / "nand")) is False


@pytest.mark.parametrize("failing", ["make_directory", "move_file_or_directory"])
def test_a_folder_that_cannot_be_placed_stops_the_install(nus_package, scratch, decrypted, monkeypatch, tmp_path, failing):
    original = getattr(nintendo.fileops, failing)
    code_dir = os.path.join(scratch, "code")
    monkeypatch.setattr(
        nintendo.fileops, failing,
        lambda src, **kwargs: False if src == code_dir else original(src = src, **kwargs))

    assert nintendo.install_wiiu_nus_package(nus_package, str(tmp_path / "nand")) is False
