# Imports
import os

# Local imports
from joybox import paths
from paths_helpers import write


def make_tree(root):
    write(root / "a.txt")
    write(root / "sub" / "b.ISO")
    write(root / "sub" / "deeper" / "c.iso")
    os.makedirs(root / "empty")
    return str(root)


###########################################################
# File lists
###########################################################

def test_file_list_is_absolute_by_default(tmp_path):
    root = make_tree(tmp_path / "root")
    assert paths.build_file_list(root) == sorted([
        os.path.join(root, "a.txt"),
        os.path.join(root, "sub", "b.ISO"),
        os.path.join(root, "sub", "deeper", "c.iso"),
    ])


def test_file_list_can_be_relative(tmp_path):
    root = make_tree(tmp_path / "root")
    assert paths.build_file_list(root, use_relative_paths = True) == [
        "a.txt", os.path.join("sub", "b.ISO"), os.path.join("sub", "deeper", "c.iso")]


def test_file_list_can_be_rebased_under_a_new_relative_path(tmp_path):
    root = make_tree(tmp_path / "root")
    listed = paths.build_file_list(root, new_relative_path = "Games", use_relative_paths = True)
    assert listed[0] == "Games/a.txt"


def test_relative_file_list_strips_only_the_leading_root(tmp_path):
    # A tree that holds its own absolute path must not lose that path twice
    root = str(tmp_path / "root")
    inner = os.path.join(root, "backup") + root
    write(os.path.join(inner, "save.dat"))
    listed = paths.build_file_list(root, use_relative_paths = True)
    assert listed == [os.path.join("backup" + root, "save.dat")]


def test_file_list_of_a_single_file(tmp_path):
    path = write(tmp_path / "rom.iso")
    assert paths.build_file_list(path) == [path]
    # Callers join each entry onto their base, so a file root comes back absolute
    assert paths.build_file_list(path, new_relative_path = "Games", use_relative_paths = True) == [path]
    os.symlink(path, tmp_path / "link.iso")
    assert paths.build_file_list(str(tmp_path / "link.iso"), ignore_symlinks = True) == []


def test_file_list_can_skip_symlinks(tmp_path):
    root = make_tree(tmp_path / "root")
    os.symlink(os.path.join(root, "a.txt"), os.path.join(root, "link.txt"))
    listed = paths.build_file_list(root, use_relative_paths = True, ignore_symlinks = True)
    assert "link.txt" not in listed
    assert "link.txt" in paths.build_file_list(root, use_relative_paths = True)


def test_file_list_of_nothing(tmp_path):
    assert paths.build_file_list(None) == []
    assert paths.build_file_list(str(tmp_path / "missing")) == []


def test_file_list_by_extension_ignores_case(tmp_path):
    root = make_tree(tmp_path / "root")
    listed = paths.build_file_list_by_extensions(root, extensions = [".iso"], use_relative_paths = True)
    assert listed == [os.path.join("sub", "b.ISO"), os.path.join("sub", "deeper", "c.iso")]
    assert len(paths.build_file_list_by_extensions(root)) == 3


###########################################################
# Directory lists
###########################################################

def test_directory_list_includes_the_root(tmp_path):
    root = make_tree(tmp_path / "root")
    assert paths.build_directory_list(root) == sorted([
        root,
        os.path.join(root, "empty"),
        os.path.join(root, "sub"),
        os.path.join(root, "sub", "deeper"),
    ])


def test_directory_list_can_be_relative(tmp_path):
    root = make_tree(tmp_path / "root")
    listed = paths.build_directory_list(root, new_relative_path = "Games", use_relative_paths = True)
    assert "Games/sub" in listed
    assert "Games/" + os.path.join("sub", "deeper") in listed


def test_directory_list_can_skip_symlinks(tmp_path):
    root = make_tree(tmp_path / "root")
    os.symlink(os.path.join(root, "sub"), os.path.join(root, "link"))
    assert os.path.join(root, "link") not in paths.build_directory_list(root, ignore_symlinks = True)
    assert os.path.join(root, "link") in paths.build_directory_list(root)


def test_directory_list_of_nothing():
    assert paths.build_directory_list(None) == []


def test_empty_and_symlinked_directory_lists(tmp_path):
    root = make_tree(tmp_path / "root")
    os.symlink(os.path.join(root, "sub"), os.path.join(root, "link"))
    assert paths.build_empty_directory_list(root) == [os.path.join(root, "empty")]
    assert paths.build_symlink_directory_list(root) == [os.path.join(root, "link")]


###########################################################
# Leaf directories
###########################################################

def test_leaf_directories_carry_counts_and_sizes(tmp_path):
    write(tmp_path / "A" / "one" / "f1", "12")
    write(tmp_path / "A" / "one" / ".hidden", "1234")
    write(tmp_path / "A" / "two" / "f2", "123")
    os.makedirs(tmp_path / "A" / ".git" / "objects")
    leaves = paths.build_leaf_directory_list(str(tmp_path))
    by_path = {leaf["path"]: leaf for leaf in leaves}
    assert set(by_path) == {str(tmp_path / "A" / "one"), str(tmp_path / "A" / "two")}
    assert by_path[str(tmp_path / "A" / "one")]["file_count"] == 1
    assert by_path[str(tmp_path / "A" / "one")]["total_size"] == 2


def test_leaf_directories_can_include_hidden_entries(tmp_path):
    write(tmp_path / "one" / ".hidden", "1234")
    leaves = paths.build_leaf_directory_list(str(tmp_path), ignore_hidden = False)
    assert leaves == [{"path": str(tmp_path / "one"), "file_count": 1, "total_size": 4}]


def test_leaf_directories_honour_excludes(tmp_path):
    write(tmp_path / "Roms" / "a" / "rom.iso")
    write(tmp_path / "Saves" / "b" / "slot.sav")
    leaves = paths.build_leaf_directory_list(str(tmp_path), excludes = ["Roms/**"])
    assert [leaf["path"] for leaf in leaves] == [str(tmp_path / "Saves" / "b")]


def test_leaf_directories_split_by_thresholds(tmp_path):
    write(tmp_path / "big" / "f1", "x" * 100)
    write(tmp_path / "many" / "f1")
    write(tmp_path / "many" / "f2")
    write(tmp_path / "many" / "f3")
    write(tmp_path / "small" / "f1")
    small, large = paths.build_leaf_directory_list(str(tmp_path), large_file_count = 2, large_total_size = 50)
    assert [leaf["path"] for leaf in small] == [str(tmp_path / "small")]
    assert sorted(leaf["path"] for leaf in large) == [str(tmp_path / "big"), str(tmp_path / "many")]


def test_leaf_directories_of_a_missing_root(tmp_path):
    assert paths.build_leaf_directory_list(str(tmp_path / "missing")) == []
    assert paths.build_leaf_directory_list(str(tmp_path / "missing"), large_file_count = 1) == ([], [])


###########################################################
# Pruning children
###########################################################

def test_child_paths_are_pruned_under_their_parents(tmp_path):
    kept = paths.prune_child_paths(["/games/a/save", "/games/a", "/games/b"])
    assert kept == ["/games/a", "/games/b"]


def test_the_bare_install_dir_token_gives_way_to_specific_paths():
    from joybox import config
    token = config.token_game_install_dir
    assert paths.prune_child_paths([token, token + "/saves"]) == [token + "/saves"]
    assert paths.prune_child_paths([token]) == [token]
