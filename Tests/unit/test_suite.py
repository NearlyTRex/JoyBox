# Imports
import ast
import collections
import os

# Third-party imports
import pytest


###########################################################
# The suite itself
#
# A test defined twice in one file silently replaces the first, which then
# never runs again and reports nothing when it would have failed. Large files
# are where this happens, so they are also kept to a size where it stays
# visible.
###########################################################

TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MAX_LINES = 900


def discover_test_files():
    found = []
    for root, dirs, files in os.walk(TESTS_DIR):
        dirs[:] = [name for name in dirs if name != "__pycache__"]
        for name in sorted(files):
            if name.startswith("test_") and name.endswith(".py"):
                found.append(os.path.join(root, name))
    return sorted(found)


TEST_FILES = discover_test_files()
TEST_IDS = [os.path.relpath(path, TESTS_DIR) for path in TEST_FILES]


def parsed(path):
    with open(path, "r", encoding = "utf-8") as handle:
        return ast.parse(handle.read())


def test_test_files_were_discovered():
    assert len(TEST_FILES) > 50


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_test_is_defined_twice(path):
    # The second definition wins and the first never runs.
    tree = parsed(path)
    seen = collections.Counter(
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_"))
    duplicates = sorted(name for name, count in seen.items() if count > 1)

    assert not duplicates, f"defined more than once: {duplicates}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_helper_is_defined_twice(path):
    # Same hazard, and harder to notice because nothing stops collecting.
    tree = parsed(path)
    seen = collections.Counter(
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    duplicates = sorted(name for name, count in seen.items() if count > 1)

    assert not duplicates, f"defined more than once: {duplicates}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_constant_is_assigned_twice(path):
    # A second module level assignment quietly replaces the first, so tests
    # above it and below it run against different values.
    tree = parsed(path)
    seen = collections.Counter()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    seen[target.id] += 1
    duplicates = sorted(name for name, count in seen.items() if count > 1)

    assert not duplicates, f"assigned more than once: {duplicates}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_module_imports_stay_at_the_top(path):
    # An import buried between sections reads as belonging to that section,
    # and the next file to be split moves the section without it.
    tree = parsed(path)
    first_statement = None
    late = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if first_statement is not None:
                late.append("line %d" % node.lineno)
        elif not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)):
            if first_statement is None:
                first_statement = node.lineno

    assert not late, f"imported below the header: {late}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_a_test_file_stays_a_readable_size(path):
    # Past this, split it into a directory of the same name with one file per
    # area and shared helpers beside them.
    with open(path, "r", encoding = "utf-8") as handle:
        length = sum(1 for _ in handle)

    assert length <= MAX_LINES, \
        f"{length} lines; split it into a package of the same name"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_every_test_file_holds_at_least_one_test(path):
    tree = parsed(path)
    tests = [node for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name.startswith("test_")]

    assert tests, "no tests in a file named like one"


def test_no_two_test_files_share_a_path():
    # importlib mode derives a module name from the path, so two files at the
    # same relative path would collide.
    assert len(TEST_FILES) == len(set(TEST_FILES))
