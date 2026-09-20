# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import backup, config


###########################################################
# Path resolution
#
# Decides where a backup lands. A wrong answer here writes a game's archive
# into another game's folder, or into the locker root.
###########################################################

ROOT = "/locker/root"


@pytest.fixture
def locker_root(monkeypatch):
    monkeypatch.setattr(backup.environment, "get_locker_root_dir", lambda locker_type = None: ROOT)
    return ROOT


def gaming(*parts):
    return "/".join([ROOT, str(config.LockerFolderType.GAMING)] + list(parts))


###########################################################
# Existing paths
###########################################################

def test_an_existing_path_is_used_as_is(tmp_path, locker_root):
    assert backup.resolve_path(path = str(tmp_path)) == str(tmp_path)


def test_an_existing_path_wins_over_categories(tmp_path, locker_root):
    resolved = backup.resolve_path(
        path = str(tmp_path),
        game_supercategory = "Games",
        game_category = "Microsoft",
        game_subcategory = "Windows")

    assert resolved == str(tmp_path)


def test_a_base_path_overrides_an_existing_path(tmp_path, locker_root):
    # The override exists so a caller can redirect a backup that already has a
    # resolved location.
    other = tmp_path / "other"
    other.mkdir()

    assert backup.resolve_path(path = str(tmp_path), base_path = str(other)) == str(other)


def test_a_missing_path_falls_back_to_the_locker_root(tmp_path, locker_root):
    assert backup.resolve_path(path = str(tmp_path / "absent")) == ROOT


def test_no_path_falls_back_to_the_locker_root(locker_root):
    assert backup.resolve_path() == ROOT


def test_a_missing_base_path_falls_back_to_the_locker_root(tmp_path, locker_root):
    resolved = backup.resolve_path(base_path = str(tmp_path / "absent"))

    assert resolved == ROOT


###########################################################
# Category layout
###########################################################

def test_a_supercategory_sits_under_gaming(locker_root):
    assert backup.resolve_path(game_supercategory = "Games") == gaming("Games")


def test_a_full_triple_builds_the_whole_path(locker_root):
    resolved = backup.resolve_path(
        game_supercategory = "Games",
        game_category = "Microsoft",
        game_subcategory = "Windows")

    assert resolved == gaming("Games", "Microsoft", "Windows")


def test_an_offset_is_appended_last(locker_root):
    resolved = backup.resolve_path(
        game_supercategory = "Games",
        game_category = "Microsoft",
        game_subcategory = "Windows",
        game_offset = "Half-Life")

    assert resolved == gaming("Games", "Microsoft", "Windows", "Half-Life")


def test_categories_build_on_a_base_path(tmp_path, locker_root):
    resolved = backup.resolve_path(
        base_path = str(tmp_path),
        game_supercategory = "Games",
        game_category = "Microsoft")

    assert resolved == "/".join([
        str(tmp_path), str(config.LockerFolderType.GAMING), "Games", "Microsoft"])


###########################################################
# Partial categories
#
# The triple is nested, so a gap stops the walk rather than skipping a level -
# otherwise a game with no category would land beside one that has one.
###########################################################

def test_a_category_without_a_supercategory_is_ignored(locker_root):
    assert backup.resolve_path(game_category = "Microsoft") == ROOT


def test_a_subcategory_without_a_category_is_ignored(locker_root):
    resolved = backup.resolve_path(
        game_supercategory = "Games", game_subcategory = "Windows")

    assert resolved == gaming("Games")


def test_an_offset_without_a_subcategory_is_ignored(locker_root):
    resolved = backup.resolve_path(
        game_supercategory = "Games",
        game_category = "Microsoft",
        game_offset = "Half-Life")

    assert resolved == gaming("Games", "Microsoft")


def test_an_offset_alone_is_ignored(locker_root):
    assert backup.resolve_path(game_offset = "Half-Life") == ROOT


@pytest.mark.parametrize("empty", ["", None])
def test_an_empty_supercategory_stops_the_walk(locker_root, empty):
    resolved = backup.resolve_path(
        game_supercategory = empty,
        game_category = "Microsoft",
        game_subcategory = "Windows")

    assert resolved == ROOT


@pytest.mark.parametrize("empty", ["", None])
def test_an_empty_category_stops_the_walk(locker_root, empty):
    resolved = backup.resolve_path(
        game_supercategory = "Games",
        game_category = empty,
        game_subcategory = "Windows")

    assert resolved == gaming("Games")


###########################################################
# Locker selection
###########################################################

def test_the_requested_locker_is_used(monkeypatch):
    seen = []

    def root(locker_type = None):
        seen.append(locker_type)
        return "/hetzner/root"

    monkeypatch.setattr(backup.environment, "get_locker_root_dir", root)
    resolved = backup.resolve_path(
        locker_type = config.LockerType.HETZNER, game_supercategory = "Games")

    assert seen == [config.LockerType.HETZNER]
    assert resolved.startswith("/hetzner/root")


def test_a_base_path_skips_the_locker_lookup(tmp_path, monkeypatch):
    # An explicit base path should not need a mounted locker.
    def root(locker_type = None):
        raise AssertionError("locker root should not be consulted")

    monkeypatch.setattr(backup.environment, "get_locker_root_dir", root)

    assert backup.resolve_path(base_path = str(tmp_path)) == str(tmp_path)


###########################################################
# Copying a tree
#
# The backup walks the source and copies each file into the same relative
# position under the destination. A file that lands flat, or that is skipped
# silently, is a backup that cannot be restored.
###########################################################

def write(path, contents = "data"):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as handle:
        handle.write(contents)
    return path


def tree(root):
    found = []
    for directory, _, filenames in os.walk(str(root)):
        for filename in filenames:
            found.append(os.path.relpath(os.path.join(directory, filename), str(root)))
    return sorted(found)


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    write(root / "top.txt", "top")
    write(root / "nested" / "deep.txt", "deep")
    return root


def test_a_tree_is_copied_into_the_destination(source, tmp_path):
    dest = tmp_path / "dest"

    assert backup.copy_files_normally(str(source), str(dest)) is True
    assert tree(dest) == [os.path.join("nested", "deep.txt"), "top.txt"]


def test_copied_contents_match_the_source(source, tmp_path):
    dest = tmp_path / "dest"
    backup.copy_files_normally(str(source), str(dest))

    with open(dest / "nested" / "deep.txt") as handle:
        assert handle.read() == "deep"


def test_the_source_is_left_in_place(source, tmp_path):
    backup.copy_files_normally(str(source), str(tmp_path / "dest"))

    assert tree(source) == [os.path.join("nested", "deep.txt"), "top.txt"]


def test_an_excluded_path_is_not_copied(source, tmp_path):
    write(source / "cache" / "junk.tmp", "junk")
    dest = tmp_path / "dest"

    backup.copy_files_normally(str(source), str(dest), exclude_paths = ["cache"])

    assert os.path.join("cache", "junk.tmp") not in tree(dest)


def test_an_empty_source_copies_nothing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    assert backup.copy_files_normally(str(empty), str(tmp_path / "dest")) is True


def test_pretending_copies_nothing(source, tmp_path):
    dest = tmp_path / "dest"

    assert backup.copy_files_normally(str(source), str(dest), pretend_run = True) is True
    assert not os.path.exists(dest)


def test_a_failed_copy_stops_the_backup(source, tmp_path, monkeypatch):
    # A partial backup that reports success is worse than a failed one.
    monkeypatch.setattr(backup.fileops, "smart_copy", lambda **kwargs: False)

    assert backup.copy_files_normally(str(source), str(tmp_path / "dest")) is False


def test_a_failed_copy_can_be_skipped(source, tmp_path, monkeypatch):
    # A failing disk should not cost the files that still read cleanly.
    monkeypatch.setattr(backup.fileops, "smart_copy", lambda **kwargs: False)
    reported = []
    monkeypatch.setattr(
        backup.fileops, "report_fileio_error",
        lambda src, dest, log, verbose, pretend: reported.append(src))

    assert backup.copy_files_normally(
        str(source), str(tmp_path / "dest"), skip_on_error = True) is True
    assert len(reported) == 2


###########################################################
# Copying with encryption
###########################################################

@pytest.fixture
def cryption(monkeypatch):
    state = {"encrypted": [], "decrypted": [], "result": True, "valid": True,
             "names": {}, "is_encrypted": True}

    monkeypatch.setattr(
        backup.cryption, "is_passphrase_valid", lambda passphrase: state["valid"])
    monkeypatch.setattr(
        backup.cryption, "generate_encrypted_filename", lambda name: name + ".enc")
    monkeypatch.setattr(
        backup.cryption, "is_file_encrypted", lambda src: state["is_encrypted"])
    monkeypatch.setattr(
        backup.cryption, "get_embedded_filename",
        lambda src, **kwargs: state["names"].get(os.path.basename(src), "restored.txt"))

    def encrypt_file(src, passphrase, output_file, **kwargs):
        state["encrypted"].append({"src": src, "out": output_file, "passphrase": passphrase})
        if state["result"]:
            write(output_file, "encrypted")
        return state["result"]

    def decrypt_file(src, passphrase, output_file, **kwargs):
        state["decrypted"].append({"src": src, "out": output_file})
        if state["result"]:
            write(output_file, "decrypted")
        return state["result"]

    monkeypatch.setattr(backup.cryption, "encrypt_file", encrypt_file)
    monkeypatch.setattr(backup.cryption, "decrypt_file", decrypt_file)
    return state


def test_each_file_is_encrypted_into_the_destination(source, cryption, tmp_path):
    dest = tmp_path / "dest"

    assert backup.copy_and_encrypt_files(str(source), str(dest), "phrase") is True
    assert tree(dest) == [os.path.join("nested", "deep.txt.enc"), "top.txt.enc"]


def test_an_encrypted_copy_keeps_the_directory_layout(source, cryption, tmp_path):
    dest = tmp_path / "dest"
    backup.copy_and_encrypt_files(str(source), str(dest), "phrase")

    outputs = sorted(entry["out"] for entry in cryption["encrypted"])
    assert outputs[0] == str(dest / "nested" / "deep.txt.enc")


def test_the_passphrase_reaches_the_encryption(source, cryption, tmp_path):
    backup.copy_and_encrypt_files(str(source), str(tmp_path / "dest"), "phrase")

    assert cryption["encrypted"][0]["passphrase"] == "phrase"


def test_an_invalid_passphrase_encrypts_nothing(source, cryption, tmp_path):
    cryption["valid"] = False

    assert backup.copy_and_encrypt_files(str(source), str(tmp_path / "dest"), "") is False
    assert cryption["encrypted"] == []


def test_a_failed_encryption_stops_the_backup(source, cryption, tmp_path):
    cryption["result"] = False

    assert backup.copy_and_encrypt_files(str(source), str(tmp_path / "dest"), "phrase") is False


def test_an_already_encrypted_file_can_be_skipped(source, cryption, tmp_path):
    dest = tmp_path / "dest"
    write(dest / "top.txt.enc", "old")

    backup.copy_and_encrypt_files(str(source), str(dest), "phrase", skip_existing = True)

    assert [os.path.basename(entry["src"]) for entry in cryption["encrypted"]] == ["deep.txt"]


def test_each_file_is_decrypted_into_the_destination(cryption, tmp_path):
    source = tmp_path / "source"
    write(source / "top.txt.enc", "encrypted")
    cryption["names"]["top.txt.enc"] = "top.txt"
    dest = tmp_path / "dest"

    assert backup.copy_and_decrypt_files(str(source), str(dest), "phrase") is True
    assert tree(dest) == ["top.txt"]


def test_a_decrypted_file_is_restored_under_its_real_name(cryption, tmp_path):
    # The stored name is opaque, so the original name comes out of the file.
    source = tmp_path / "source"
    write(source / "abc123.enc", "encrypted")
    cryption["names"]["abc123.enc"] = "Original Name.txt"
    dest = tmp_path / "dest"

    backup.copy_and_decrypt_files(str(source), str(dest), "phrase")

    assert tree(dest) == ["Original Name.txt"]


def test_a_plain_file_keeps_its_name_when_decrypting(cryption, tmp_path):
    source = tmp_path / "source"
    write(source / "notes.txt", "plain")
    cryption["is_encrypted"] = False
    dest = tmp_path / "dest"

    backup.copy_and_decrypt_files(str(source), str(dest), "phrase")

    assert tree(dest) == ["notes.txt"]


def test_an_unreadable_name_stops_the_restore(cryption, tmp_path):
    source = tmp_path / "source"
    write(source / "abc123.enc", "encrypted")
    cryption["names"]["abc123.enc"] = None

    assert backup.copy_and_decrypt_files(str(source), str(tmp_path / "dest"), "phrase") is False


def test_an_invalid_passphrase_decrypts_nothing(cryption, tmp_path):
    source = tmp_path / "source"
    write(source / "top.txt.enc", "encrypted")
    cryption["valid"] = False

    assert backup.copy_and_decrypt_files(str(source), str(tmp_path / "dest"), "") is False
    assert cryption["decrypted"] == []


###########################################################
# Choosing how to copy
###########################################################

@pytest.fixture
def routes(monkeypatch):
    calls = []
    for name in ["copy_files_normally", "copy_and_encrypt_files", "copy_and_decrypt_files"]:
        monkeypatch.setattr(
            backup, name,
            (lambda name: lambda **kwargs: calls.append((name, kwargs)) or True)(name))
    monkeypatch.setattr(
        backup.lockerinfo.LockerInfo, "get_passphrase", lambda self: "from-locker")
    return calls


def test_no_cryption_copies_plainly(routes):
    assert backup.copy_files("/in", "/out") is True
    assert routes[0][0] == "copy_files_normally"


def test_encrypting_routes_to_the_encrypted_copy(routes):
    backup.copy_files("/in", "/out", cryption_type = config.CryptionType.ENCRYPT)

    assert routes[0][0] == "copy_and_encrypt_files"


def test_decrypting_routes_to_the_decrypted_copy(routes):
    backup.copy_files("/in", "/out", cryption_type = config.CryptionType.DECRYPT)

    assert routes[0][0] == "copy_and_decrypt_files"


def test_the_passphrase_comes_from_the_locker(routes):
    # The caller never passes a passphrase; it belongs to the locker being
    # written to.
    backup.copy_files("/in", "/out", cryption_type = config.CryptionType.ENCRYPT)

    assert routes[0][1]["passphrase"] == "from-locker"


def test_a_plain_copy_needs_no_locker(routes):
    backup.copy_files("/in", "/out")

    assert "passphrase" not in routes[0][1]


###########################################################
# Archiving a folder
###########################################################

@pytest.fixture
def archiving(monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    state = {"archived": [], "moved": [], "emptied": [], "scratch": str(scratch),
             "result": True}

    monkeypatch.setattr(
        backup.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(scratch)))

    def create_archive_from_folder(archive_file, source_dir, **kwargs):
        state["archived"].append({"archive": archive_file, "source": source_dir,
                                  "options": kwargs})
        return state["result"]

    def smart_move(src, dest, **kwargs):
        state["moved"].append((src, dest))
        write(dest, "archive")
        return True

    monkeypatch.setattr(backup.archive, "create_archive_from_folder", create_archive_from_folder)
    monkeypatch.setattr(backup.fileops, "smart_move", smart_move)
    monkeypatch.setattr(
        backup.fileops, "remove_directory_contents",
        lambda src, **kwargs: state["emptied"].append(src) or True)
    return state


def test_a_folder_is_archived_to_the_output_it_was_given(source, archiving, tmp_path):
    # The output path is the one the caller passed, not one built from names
    # belonging to another function.
    output = tmp_path / "out"

    assert backup.archive_folder(str(source), str(output), "Backup") is True
    assert archiving["moved"][0][1] == str(output / "Backup.7z")


def test_an_archive_is_named_for_its_type(source, archiving, tmp_path):
    backup.archive_folder(
        str(source), str(tmp_path / "out"), "Backup",
        archive_type = config.ArchiveFileType.ZIP)

    assert archiving["moved"][0][1].endswith("Backup.zip")


def test_an_archive_extension_carries_a_single_dot(source, archiving, tmp_path):
    backup.archive_folder(str(source), str(tmp_path / "out"), "Backup")

    assert ".." not in archiving["moved"][0][1]


def test_an_archive_is_built_in_the_scratch_directory(source, archiving, tmp_path):
    # Building straight into the destination leaves a half written archive
    # there if the run is interrupted.
    backup.archive_folder(str(source), str(tmp_path / "out"), "Backup")

    assert archiving["archived"][0]["archive"] == os.path.join(archiving["scratch"], "Backup.7z")


def test_an_archive_is_split_into_volumes(source, archiving, tmp_path):
    # Remote lockers reject single files past a few gigabytes.
    backup.archive_folder(str(source), str(tmp_path / "out"), "Backup")

    assert archiving["archived"][0]["options"]["volume_size"] == "4092m"


def test_excluded_paths_are_kept_out_of_the_archive(source, archiving, tmp_path):
    backup.archive_folder(
        str(source), str(tmp_path / "out"), "Backup", exclude_paths = ["cache"])

    assert archiving["archived"][0]["options"]["excludes"] == ["cache"]


def test_the_output_can_be_emptied_first(source, archiving, tmp_path):
    output = tmp_path / "out"

    backup.archive_folder(str(source), str(output), "Backup", clean_output = True)

    assert archiving["emptied"] == [str(output)]


def test_the_output_is_kept_by_default(source, archiving, tmp_path):
    backup.archive_folder(str(source), str(tmp_path / "out"), "Backup")

    assert archiving["emptied"] == []


def test_a_failed_archive_moves_nothing(source, archiving, tmp_path):
    archiving["result"] = False

    assert backup.archive_folder(str(source), str(tmp_path / "out"), "Backup") is False
    assert archiving["moved"] == []


def test_archiving_without_a_scratch_directory_reports_failure(source, monkeypatch, tmp_path):
    monkeypatch.setattr(
        backup.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    assert backup.archive_folder(str(source), str(tmp_path / "out"), "Backup") is False


###########################################################
# Archiving sub-folders
###########################################################

def test_each_sub_folder_becomes_its_own_archive(archiving, tmp_path):
    root = tmp_path / "source"
    write(root / "Gaming" / "GameOne" / "file.txt")
    write(root / "Gaming" / "GameTwo" / "file.txt")
    output = tmp_path / "out"

    backup.archive_sub_folders(str(root), str(output))

    assert sorted(dest for _, dest in archiving["moved"]) == [
        str(output / "Gaming" / "GameOne.7z"),
        str(output / "Gaming" / "GameTwo.7z"),
    ]


def test_a_sub_folder_archive_extension_carries_a_single_dot(archiving, tmp_path):
    root = tmp_path / "source"
    write(root / "Gaming" / "GameOne" / "file.txt")

    backup.archive_sub_folders(str(root), str(tmp_path / "out"))

    assert ".." not in archiving["moved"][0][1]


def test_a_loose_file_is_not_archived(archiving, tmp_path):
    # Only directories become archives; a stray file at the top is not one.
    root = tmp_path / "source"
    write(root / "Gaming" / "notes.txt")

    backup.archive_sub_folders(str(root), str(tmp_path / "out"))

    assert archiving["moved"] == []


def test_an_excluded_top_folder_is_skipped(archiving, tmp_path):
    root = tmp_path / "source"
    write(root / "Gaming" / "GameOne" / "file.txt")
    write(root / "Cache" / "Junk" / "file.txt")

    backup.archive_sub_folders(str(root), str(tmp_path / "out"), exclude_paths = ["Cache"])

    assert len(archiving["moved"]) == 1
