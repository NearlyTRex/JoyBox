# Imports
import ast
import collections
import os

# Third-party imports
import pytest

# Local imports
from meta_helpers import FUNCTION_DEFS, SUITE_DIRS, TEST_FILES, TEST_IDS, collected_tests, parse_sample, parsed


###########################################################
# File hygiene
#
# A test defined twice in one file silently replaces the first, which then
# never runs again and reports nothing when it would have failed. Large files
# are where this happens, so they are also kept to a size where it stays
# visible.
###########################################################

MAX_LINES = 900


def duplicated(names):
    return sorted(name for name, count in collections.Counter(names).items() if count > 1)


# Lines of imports that come after the first real statement
def late_imports(tree):
    first_statement = None
    late = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if first_statement is not None:
                late.append(node.lineno)
        elif not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)):
            if first_statement is None:
                first_statement = node.lineno
    return late


def test_test_files_were_discovered():
    assert len(TEST_FILES) > 500


def test_every_suite_was_discovered():
    # These checks only guard a suite whose files they see.
    empty = [suite for suite in SUITE_DIRS if not any(path.startswith(suite + os.sep) for path in TEST_FILES)]

    assert not empty, f"no tests found under {empty}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_test_is_defined_twice(path):
    # The second definition wins and the first never runs.
    duplicates = duplicated(
        node.name for node in parsed(path).body if isinstance(node, FUNCTION_DEFS) and node.name.startswith("test_"))

    assert not duplicates, f"defined more than once: {duplicates}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_test_method_is_defined_twice_within_a_class(path):
    # The same hazard, one level down.
    duplicates = {
        node.name: names for node in parsed(path).body if isinstance(node, ast.ClassDef)
        for names in [duplicated(
            member.name for member in node.body if isinstance(member, FUNCTION_DEFS) and member.name.startswith("test_"))]
        if names}

    assert not duplicates, f"defined more than once: {duplicates}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_helper_is_defined_twice(path):
    # The same hazard, and harder to notice because nothing stops collecting.
    duplicates = duplicated(node.name for node in parsed(path).body if isinstance(node, FUNCTION_DEFS + (ast.ClassDef,)))

    assert not duplicates, f"defined more than once: {duplicates}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_constant_is_assigned_twice(path):
    # A second module level assignment quietly replaces the first, so tests
    # above it and below it run against different values.
    duplicates = duplicated(
        target.id for node in parsed(path).body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name) and target.id.isupper())

    assert not duplicates, f"assigned more than once: {duplicates}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_module_imports_stay_at_the_top(path):
    # An import buried between sections reads as belonging to that section,
    # and the next file to be split moves the section without it.
    late = late_imports(parsed(path))

    assert not late, f"imported below the header at line(s) {late}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_a_test_file_stays_a_readable_size(path):
    # Past this, split it into a directory of the same name with one file per
    # area and shared helpers beside them.
    with open(path, "r", encoding = "utf-8") as handle:
        length = sum(1 for _ in handle)

    assert length <= MAX_LINES, f"{length} lines; split it into a package of the same name"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_every_test_file_holds_at_least_one_test(path):
    assert collected_tests(parsed(path)), "no tests in a file named like one"


def test_no_two_test_files_share_a_path():
    # importlib mode derives a module name from the path, so two files at the
    # same relative path would collide.
    assert len(TEST_FILES) == len(set(TEST_FILES))

###########################################################
# The checks themselves
###########################################################

def test_duplicates_are_found_in_any_iterable():
    assert duplicated(iter(["b", "a", "b", "c", "a"])) == ["a", "b"]
    assert duplicated([]) == []


def test_late_imports_are_reported_but_a_docstring_and_the_header_are_not(tmp_path):
    tree = parse_sample(tmp_path, (
        '"""Docstring."""\n'
        "import os\n"
        "from sys import path\n"
        "LIMIT = 3\n"
        "import json\n"
        "def f():\n"
        "    import re\n"))

    assert late_imports(tree) == [5]
