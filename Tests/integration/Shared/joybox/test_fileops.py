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
    root = tmp_path / "tree"
    root.mkdir()
    inner = write(str(root / "inner.txt"))

    fileops.chmod_file_or_directory(str(root), "600")

    assert oct(os.stat(inner).st_mode & 0o777) == "0o600"


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
