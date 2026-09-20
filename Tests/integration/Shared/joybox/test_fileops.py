# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops


###########################################################
# fileops against a real filesystem
#
# Most of this deletes, moves or overwrites. -p is documented as a safe dry
# run, so every destructive path has to honour it.
###########################################################

def write(path, contents = "content"):
    with open(path, "w") as target:
        target.write(contents)
    return path


def read(path):
    with open(path, "r") as target:
        return target.read()


###########################################################
# Creating
###########################################################

def test_touch_creates_an_empty_file(tmp_path):
    target = str(tmp_path / "new.txt")

    assert fileops.touch_file(target) is True
    assert os.path.isfile(target)
    assert read(target) == ""


def test_touch_writes_contents(tmp_path):
    target = str(tmp_path / "new.txt")
    fileops.touch_file(target, contents = "hello")

    assert read(target) == "hello"


def test_touch_creates_missing_parent_directories(tmp_path):
    target = str(tmp_path / "deep" / "nested" / "new.txt")

    assert fileops.touch_file(target) is True
    assert os.path.isfile(target)


def test_touch_honours_an_explicit_encoding(tmp_path):
    # open()'s third positional argument is buffering, not encoding.
    target = str(tmp_path / "encoded.txt")

    assert fileops.touch_file(target, contents = "café", encoding = "utf-8") is True
    assert os.path.isfile(target)
    with open(target, "r", encoding = "utf-8") as written:
        assert written.read() == "café"


def test_make_directory_creates_nested_paths(tmp_path):
    target = str(tmp_path / "a" / "b" / "c")

    assert fileops.make_directory(target) is True
    assert os.path.isdir(target)


def test_a_temporary_directory_is_created_and_usable():
    created, temp_dir = fileops.create_temporary_directory()

    assert created is True
    assert os.path.isdir(temp_dir)

    fileops.remove_directory(temp_dir)


def test_a_temporary_file_is_created_and_usable():
    created, temp_file = fileops.create_temporary_file(suffix = ".txt")

    assert created is True
    assert os.path.isfile(temp_file)
    assert temp_file.endswith(".txt")

    fileops.remove_file(temp_file)


def test_the_temporary_helpers_report_the_same_way():
    # Both are unpacked as a pair by their callers, and one of them returning
    # a bare path would be read as a two character path.
    file_result = fileops.create_temporary_file()
    dir_result = fileops.create_temporary_directory()

    assert isinstance(file_result, tuple) and len(file_result) == 2
    assert isinstance(dir_result, tuple) and len(dir_result) == 2
    assert file_result[0] is True and dir_result[0] is True

    fileops.remove_file(file_result[1])
    fileops.remove_directory(dir_result[1])


def test_two_temporary_files_do_not_collide():
    first_ok, first = fileops.create_temporary_file()
    second_ok, second = fileops.create_temporary_file()

    assert first != second

    fileops.remove_file(first)
    fileops.remove_file(second)


@pytest.mark.parametrize("creator", [
    fileops.create_temporary_file,
    fileops.create_temporary_directory,
])
def test_pretending_creates_nothing_temporary(creator):
    created, result = creator(pretend_run = True)

    assert created is False
    assert not os.path.exists(result)


###########################################################
# Editing
###########################################################

def test_strings_are_replaced_in_place(tmp_path):
    target = write(str(tmp_path / "config.txt"), "host = old\nport = 1\n")

    assert fileops.replace_strings_in_file(
        target, [{"from": "old", "to": "new"}]) is True
    assert "host = new" in read(target)


def test_several_replacements_all_apply(tmp_path):
    target = write(str(tmp_path / "config.txt"), "a b\n")

    fileops.replace_strings_in_file(
        target, [{"from": "a", "to": "1"}, {"from": "b", "to": "2"}])

    assert read(target) == "1 2\n"


def test_replacing_in_a_missing_file_reports_failure(tmp_path):
    assert fileops.replace_strings_in_file(
        str(tmp_path / "absent.txt"), [{"from": "a", "to": "b"}]) is False


def test_replacing_in_a_directory_reports_failure(tmp_path):
    assert fileops.replace_strings_in_file(
        str(tmp_path), [{"from": "a", "to": "b"}]) is False


def test_a_line_is_appended(tmp_path):
    target = write(str(tmp_path / "log.txt"), "first\n")

    assert fileops.append_line_to_file(target, "second") is True
    assert "first" in read(target)
    assert "second" in read(target)


def test_file_contents_are_sorted(tmp_path):
    target = write(str(tmp_path / "list.txt"), "c\na\nb\n")

    assert fileops.sort_file_contents(target) is True
    assert read(target).split() == ["a", "b", "c"]


###########################################################
# Copying and moving
###########################################################

def test_copy_leaves_the_source(tmp_path):
    source = write(str(tmp_path / "a.txt"))
    destination = str(tmp_path / "b.txt")

    fileops.copy_file_or_directory(source, destination)

    assert os.path.isfile(source)
    assert read(destination) == "content"


def test_move_removes_the_source(tmp_path):
    source = write(str(tmp_path / "a.txt"))
    destination = str(tmp_path / "b.txt")

    fileops.move_file_or_directory(source, destination)

    assert not os.path.exists(source)
    assert read(destination) == "content"


def test_a_directory_copies_with_its_contents(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    write(str(source_dir / "inner.txt"), "inner")
    destination = str(tmp_path / "dst")

    fileops.copy_file_or_directory(str(source_dir), destination)

    assert read(os.path.join(destination, "inner.txt")) == "inner"


###########################################################
# Removing
###########################################################

def test_a_file_is_removed(tmp_path):
    target = write(str(tmp_path / "a.txt"))

    assert fileops.remove_file(target) is True
    assert not os.path.exists(target)


def test_a_directory_tree_is_removed(tmp_path):
    target = tmp_path / "tree"
    target.mkdir()
    write(str(target / "inner.txt"))

    assert fileops.remove_directory(str(target)) is True
    assert not os.path.exists(str(target))


def test_directory_contents_are_removed_but_the_directory_stays(tmp_path):
    target = tmp_path / "tree"
    target.mkdir()
    write(str(target / "inner.txt"))
    (target / "sub").mkdir()

    assert fileops.remove_directory_contents(str(target)) is True
    assert os.path.isdir(str(target))
    assert os.listdir(str(target)) == []


def test_empty_directories_are_pruned(tmp_path):
    root = tmp_path / "root"
    (root / "empty").mkdir(parents = True)
    (root / "full").mkdir()
    write(str(root / "full" / "inner.txt"))

    fileops.remove_empty_directories(str(root))

    assert not os.path.exists(str(root / "empty"))
    assert os.path.isdir(str(root / "full"))


###########################################################
# Symlinks
###########################################################

def test_a_symlink_is_created_and_resolves(tmp_path):
    source = write(str(tmp_path / "real.txt"))
    link = str(tmp_path / "link.txt")

    fileops.create_symlink(source, link)

    assert os.path.islink(link)
    assert os.path.realpath(link) == os.path.realpath(source)


def test_removing_a_symlink_leaves_the_target(tmp_path):
    source = write(str(tmp_path / "real.txt"))
    link = str(tmp_path / "link.txt")
    fileops.create_symlink(source, link)

    fileops.remove_symlink(link)

    assert not os.path.exists(link)
    assert os.path.isfile(source), "removing the link must not touch the target"


###########################################################
# Permissions
###########################################################

def test_permissions_are_applied(tmp_path):
    # Permissions are an octal string, not an int: perms is parsed with
    # int(str(perms), base=8), so 0o600 becomes "384" and fails.
    target = write(str(tmp_path / "secret.env"))

    assert fileops.chmod_file_or_directory(target, "600") is True
    assert oct(os.stat(target).st_mode & 0o777) == "0o600"


def test_a_non_octal_permission_string_reports_failure(tmp_path):
    target = write(str(tmp_path / "secret.env"))
    before = os.stat(target).st_mode & 0o777

    assert fileops.chmod_file_or_directory(target, "not-octal") is False
    assert os.stat(target).st_mode & 0o777 == before


def test_directory_permissions_apply_to_contents(tmp_path):
    # Directories need their traverse bit, so a tree of 600 files is given
    # 700 directories; the root is a directory too and takes the same.
    root = tmp_path / "tree"
    root.mkdir()
    inner = write(str(root / "inner.txt"))

    fileops.chmod_file_or_directory(str(root), "600", dperms = "700")

    assert oct(os.stat(inner).st_mode & 0o777) == "0o600"
    assert oct(os.stat(str(root)).st_mode & 0o777) == "0o700"


def test_a_file_is_marked_executable(tmp_path):
    target = write(str(tmp_path / "script.sh"), "#!/bin/sh\n")

    fileops.mark_as_executable(target)

    assert os.access(target, os.X_OK)


###########################################################
# Pretend run
#
# A path that forgets the guard destroys data during what looked like a rehearsal.
###########################################################

def test_pretend_run_does_not_create(tmp_path):
    target = str(tmp_path / "new.txt")

    assert fileops.touch_file(target, pretend_run = True) is True
    assert not os.path.exists(target)


def test_pretend_run_does_not_make_directories(tmp_path):
    target = str(tmp_path / "new-dir")

    fileops.make_directory(target, pretend_run = True)

    assert not os.path.exists(target)


def test_pretend_run_does_not_remove_a_file(tmp_path):
    target = write(str(tmp_path / "a.txt"))

    fileops.remove_file(target, pretend_run = True)

    assert os.path.isfile(target)


def test_pretend_run_does_not_remove_a_directory(tmp_path):
    target = tmp_path / "tree"
    target.mkdir()
    write(str(target / "inner.txt"))

    fileops.remove_directory(str(target), pretend_run = True)

    assert os.path.isdir(str(target))


def test_pretend_run_does_not_empty_a_directory(tmp_path):
    target = tmp_path / "tree"
    target.mkdir()
    write(str(target / "inner.txt"))

    fileops.remove_directory_contents(str(target), pretend_run = True)

    assert os.listdir(str(target)) == ["inner.txt"]


def test_pretend_run_does_not_edit_a_file(tmp_path):
    target = write(str(tmp_path / "config.txt"), "host = old\n")

    fileops.replace_strings_in_file(
        target, [{"from": "old", "to": "new"}], pretend_run = True)

    assert read(target) == "host = old\n"


def test_pretend_run_does_not_append(tmp_path):
    target = write(str(tmp_path / "log.txt"), "first\n")

    fileops.append_line_to_file(target, "second", pretend_run = True)

    assert read(target) == "first\n"


def test_pretend_run_does_not_copy(tmp_path):
    source = write(str(tmp_path / "a.txt"))
    destination = str(tmp_path / "b.txt")

    fileops.copy_file_or_directory(source, destination, pretend_run = True)

    assert not os.path.exists(destination)


def test_pretend_run_does_not_move(tmp_path):
    source = write(str(tmp_path / "a.txt"))
    destination = str(tmp_path / "b.txt")

    fileops.move_file_or_directory(source, destination, pretend_run = True)

    assert os.path.isfile(source)
    assert not os.path.exists(destination)


###########################################################
# Headers
#
# Used to tell a real archive from a file with the right extension.
###########################################################

def test_a_matching_byte_header_is_recognised(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04rest of the file")

    assert fileops.is_file_correctly_headered(str(target), b"PK\x03\x04") is True


def test_a_matching_text_header_is_recognised(tmp_path):
    target = tmp_path / "script.sh"
    target.write_text("#!/bin/bash\necho hi\n")

    assert fileops.is_file_correctly_headered(str(target), "#!/bin/bash") is True


def test_a_wrong_header_is_rejected(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"not an archive at all")

    assert fileops.is_file_correctly_headered(str(target), b"PK\x03\x04") is False


def test_a_truncated_file_is_rejected(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK")

    assert fileops.is_file_correctly_headered(str(target), b"PK\x03\x04") is False


def test_a_missing_file_has_no_header(tmp_path):
    assert fileops.is_file_correctly_headered(str(tmp_path / "absent"), b"PK") is False


def test_a_directory_has_no_header(tmp_path):
    assert fileops.is_file_correctly_headered(str(tmp_path), b"PK") is False


###########################################################
# Symlinks
###########################################################

def test_a_symlink_is_created(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("content")
    link = tmp_path / "link.txt"

    assert fileops.create_symlink(str(target), str(link)) is True
    assert link.is_symlink()
    assert link.read_text() == "content"


def test_a_symlink_creates_its_parent_directory(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("content")
    link = tmp_path / "nested" / "deeper" / "link.txt"
    fileops.create_symlink(str(target), str(link))

    assert link.is_symlink()


def test_a_symlink_replaces_an_existing_file(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("new content")
    link = tmp_path / "link.txt"
    link.write_text("stale content")
    fileops.create_symlink(str(target), str(link))

    assert link.is_symlink()
    assert link.read_text() == "new content"


def test_a_symlink_can_refuse_to_replace(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("content")
    link = tmp_path / "link.txt"
    link.write_text("stale content")

    assert fileops.create_symlink(str(target), str(link), overwrite = False) is False
    assert link.read_text() == "stale content"


def test_a_symlink_to_a_directory_is_marked_as_one(tmp_path):
    target = tmp_path / "realdir"
    target.mkdir()
    (target / "inside.txt").write_text("content")
    link = tmp_path / "linkdir"
    fileops.create_symlink(str(target), str(link))

    assert link.is_symlink()
    assert (link / "inside.txt").read_text() == "content"


def test_a_symlink_resolves_to_its_target(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("content")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    assert fileops.resolve_symlink(str(link)) == str(target.resolve())


def test_a_plain_file_resolves_to_nothing(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("content")

    assert fileops.resolve_symlink(str(target)) is None


def test_a_symlink_is_removed_without_its_target(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("content")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    assert fileops.remove_symlink(str(link)) is True
    assert not link.exists()
    assert target.exists()


def test_a_symlinked_directory_becomes_a_real_one(tmp_path):
    # Wine prefixes link the user directories out; replacing them keeps a
    # game's writes inside the prefix.
    real = tmp_path / "real"
    real.mkdir()
    (real / "keepme.txt").write_text("content")
    root = tmp_path / "prefix"
    root.mkdir()
    (root / "Documents").symlink_to(real)

    assert fileops.replace_symlinked_directories(str(root)) is True
    assert (root / "Documents").is_dir()
    assert not (root / "Documents").is_symlink()
    assert real.exists()


def test_replacing_symlinks_leaves_real_directories_alone(tmp_path):
    root = tmp_path / "prefix"
    (root / "Documents").mkdir(parents = True)
    (root / "Documents" / "file.txt").write_text("content")
    fileops.replace_symlinked_directories(str(root))

    assert (root / "Documents" / "file.txt").read_text() == "content"


###########################################################
# Renaming in place
###########################################################

def test_every_name_is_lowercased(tmp_path):
    root = tmp_path / "tree"
    (root / "SubDir").mkdir(parents = True)
    (root / "SubDir" / "FILE.TXT").write_text("content")
    (root / "Another.DAT").write_text("content")

    assert fileops.lowercase_all_paths(str(root)) is True
    found = {name for _, _, files in os.walk(str(root)) for name in files}
    assert found == {"file.txt", "another.dat"}


def test_lowercasing_renames_directories_too(tmp_path):
    root = tmp_path / "tree"
    (root / "SubDir").mkdir(parents = True)
    (root / "SubDir" / "file.txt").write_text("content")
    fileops.lowercase_all_paths(str(root))

    assert (root / "subdir").is_dir()


def test_lowercasing_an_already_lowercase_tree_changes_nothing(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file.txt").write_text("content")
    fileops.lowercase_all_paths(str(root))

    assert (root / "file.txt").read_text() == "content"


def test_pretending_does_not_lowercase(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "FILE.TXT").write_text("content")
    fileops.lowercase_all_paths(str(root), pretend_run = True)

    assert (root / "FILE.TXT").exists()


def test_invalid_characters_are_removed_from_filenames(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "bad name. ").write_text("content")

    assert fileops.sanitize_filenames(str(root)) is True
    assert "bad name. " not in os.listdir(str(root))


def test_sanitizing_can_be_limited_to_an_extension(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "keep me. ").write_text("content")
    (root / "clean me. .txt").write_text("content")
    fileops.sanitize_filenames(str(root), extension = ".txt")

    assert "keep me. " in os.listdir(str(root))


def test_sanitizing_leaves_a_clean_name_alone(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "already clean.txt").write_text("content")
    fileops.sanitize_filenames(str(root))

    assert "already clean.txt" in os.listdir(str(root))


###########################################################
# Permissions
###########################################################

def test_a_file_is_made_executable(tmp_path):
    target = tmp_path / "tool"
    target.write_text("#!/bin/sh\n")

    assert fileops.mark_as_executable(str(target)) is True
    assert os.access(str(target), os.X_OK)


def test_permissions_are_set_from_an_octal_string(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("TOKEN=x\n")
    fileops.chmod_file_or_directory(str(target), "600")

    assert oct(os.stat(str(target)).st_mode)[-3:] == "600"


def test_directory_permissions_can_differ_from_file_ones(tmp_path):
    root = tmp_path / "tree"
    (root / "nested").mkdir(parents = True)
    (root / "file.txt").write_text("content")
    fileops.chmod_file_or_directory(str(root), "600", dperms = "700")

    assert oct(os.stat(str(root / "nested")).st_mode)[-3:] == "700"
    assert oct(os.stat(str(root / "file.txt")).st_mode)[-3:] == "600"


###########################################################
# Recycling
#
# A delete that stays reversible, which is what makes the sync safe to run.
###########################################################

def test_a_file_is_moved_into_the_recycle_bin(tmp_path):
    root = tmp_path / "locker"
    root.mkdir()
    target = root / "game.zip"
    target.write_text("content")

    assert fileops.recycle_file(str(target), str(root)) is True
    assert not target.exists()
    assert (root / ".recycle_bin" / "game.zip").read_text() == "content"


def test_a_nested_file_keeps_its_layout_in_the_bin(tmp_path):
    root = tmp_path / "locker"
    (root / "Roms" / "Nintendo").mkdir(parents = True)
    target = root / "Roms" / "Nintendo" / "game.zip"
    target.write_text("content")
    fileops.recycle_file(str(target), str(root))

    assert (root / ".recycle_bin" / "Roms" / "Nintendo" / "game.zip").exists()


def test_a_second_file_of_the_same_name_is_kept_alongside(tmp_path):
    # Recycling twice must not silently discard the first copy.
    root = tmp_path / "locker"
    root.mkdir()
    (root / "game.zip").write_text("first")
    fileops.recycle_file(str(root / "game.zip"), str(root))
    (root / "game.zip").write_text("second")
    fileops.recycle_file(str(root / "game.zip"), str(root))

    recycled = sorted(os.listdir(str(root / ".recycle_bin")))
    assert len(recycled) == 2


def test_recycling_a_missing_file_is_success(tmp_path):
    root = tmp_path / "locker"
    root.mkdir()

    assert fileops.recycle_file(str(root / "absent.zip"), str(root)) is True


def test_a_file_already_in_the_bin_is_left_there(tmp_path):
    root = tmp_path / "locker"
    binned = root / ".recycle_bin"
    binned.mkdir(parents = True)
    target = binned / "game.zip"
    target.write_text("content")

    assert fileops.recycle_file(str(target), str(root)) is True
    assert target.exists()


def test_a_custom_bin_name_is_used(tmp_path):
    root = tmp_path / "locker"
    root.mkdir()
    (root / "game.zip").write_text("content")
    fileops.recycle_file(str(root / "game.zip"), str(root), recycle_folder = ".trash")

    assert (root / ".trash" / "game.zip").exists()


def test_the_recycle_bin_is_emptied(tmp_path):
    root = tmp_path / "locker"
    root.mkdir()
    (root / "game.zip").write_text("content")
    fileops.recycle_file(str(root / "game.zip"), str(root))

    assert fileops.empty_recycle_bin(str(root)) is True
    assert not any(os.scandir(str(root / ".recycle_bin"))) or \
        not (root / ".recycle_bin").exists()


def test_emptying_an_absent_bin_is_success(tmp_path):
    root = tmp_path / "locker"
    root.mkdir()

    assert fileops.empty_recycle_bin(str(root)) is True


###########################################################
# Smart transfers
###########################################################

def test_a_smart_copy_creates_missing_parents(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("content")
    target = tmp_path / "a" / "b" / "target.txt"

    assert fileops.smart_copy(str(source), str(target)) is True
    assert target.read_text() == "content"


def test_a_smart_copy_leaves_the_source(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("content")
    fileops.smart_copy(str(source), str(tmp_path / "target.txt"))

    assert source.exists()


def test_a_smart_move_removes_the_source(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("content")
    fileops.smart_move(str(source), str(tmp_path / "target.txt"))

    assert not source.exists()
    assert (tmp_path / "target.txt").read_text() == "content"


def test_a_smart_copy_can_skip_an_existing_target(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("new")
    target = tmp_path / "target.txt"
    target.write_text("old")
    fileops.smart_copy(str(source), str(target), skip_existing = True)

    assert target.read_text() == "old"


def test_a_smart_copy_skips_an_identical_target(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("same")
    target = tmp_path / "target.txt"
    target.write_text("same")

    assert fileops.smart_copy(str(source), str(target), skip_identical = True) is True
    assert target.read_text() == "same"


def test_a_glob_copies_every_match(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ["a.cue", "b.cue", "c.bin"]:
        (source / name).write_text(name)
    target = tmp_path / "target"

    fileops.smart_copy(str(source / "*.cue"), str(target))
    assert sorted(os.listdir(str(target))) == ["a.cue", "b.cue"]


def test_a_directory_copies_with_its_tree(tmp_path):
    source = tmp_path / "source"
    (source / "nested").mkdir(parents = True)
    (source / "nested" / "file.txt").write_text("content")
    target = tmp_path / "target"

    fileops.smart_copy(str(source), str(target))
    assert (target / "nested" / "file.txt").read_text() == "content"


###########################################################
# Contents
###########################################################

def test_contents_are_copied_without_the_directory_itself(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content")
    target = tmp_path / "target"
    target.mkdir()

    assert fileops.copy_contents(str(source), str(target)) is True
    assert (target / "file.txt").exists()
    assert not (target / "source").exists()


def test_contents_are_moved_without_the_directory_itself(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content")
    target = tmp_path / "target"
    target.mkdir()
    fileops.move_contents(str(source), str(target))

    assert (target / "file.txt").exists()
    assert not (source / "file.txt").exists()


def test_moving_contents_keeps_the_source_directory(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content")
    target = tmp_path / "target"
    target.mkdir()
    fileops.move_contents(str(source), str(target))

    assert source.is_dir()


def test_the_directory_itself_is_chmodded(tmp_path):
    # Its contents are unreachable otherwise when the directory is the read
    # only one, which is exactly what an extracted iso leaves behind.
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file.txt").write_text("content")
    os.chmod(str(root), 0o555)
    fileops.chmod_file_or_directory(str(root), "777")

    assert oct(os.stat(str(root)).st_mode)[-3:] == "777"


def test_a_read_only_directory_can_then_be_emptied(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file.txt").write_text("content")
    os.chmod(str(root), 0o555)
    fileops.chmod_file_or_directory(str(root), "777")

    assert fileops.remove_directory_contents(str(root)) is True
    assert os.listdir(str(root)) == []


def test_the_directory_takes_the_directory_permissions(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "file.txt").write_text("content")
    fileops.chmod_file_or_directory(str(root), "644", dperms = "755")

    assert oct(os.stat(str(root)).st_mode)[-3:] == "755"
