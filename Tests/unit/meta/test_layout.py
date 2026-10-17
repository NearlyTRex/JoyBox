# Imports
import ast
import os

# Third-party imports
import pytest

# Local imports
from meta_helpers import FUNCTION_DEFS, REPO_ROOT, SUITE_DIRS, TESTS_DIR, parsed


###########################################################
# Layout
#
# Each suite mirrors the repository: a test lives at the path of the code it
# covers. A test module that outgrows the size limit becomes a directory of
# the same name, test_<module>/, holding test_<area>.py files, a conftest.py
# and a <module>_helpers.py they share. The hazards are quiet: a file that
# holds tests but is not named test_*.py is never collected, and a directory
# that mirrors nothing puts tests where nobody looks for them.
###########################################################

# Files in a split package that are not test modules by design
SUPPORT_FILES = {"conftest.py"}

# Directories that mirror nothing on purpose: meta holds tests of the suite itself
NON_MIRROR_DIRECTORIES = {os.path.join("unit", "meta")}

SOURCE_EXTENSIONS = (".py", ".sh")


def walk_directories(suite_dirs):
    for suite_dir in [suite_dirs] if isinstance(suite_dirs, str) else suite_dirs:
        for root, dirs, _ in os.walk(suite_dir):
            dirs[:] = sorted(name for name in dirs if name != "__pycache__" and not name.startswith("."))
            yield root, dirs


# Every test_<module> directory under the suites
def discover_split_packages(suite_dirs = SUITE_DIRS):
    return sorted(os.path.join(root, name) for root, dirs in walk_directories(suite_dirs)
                  for name in dirs if name.startswith("test_"))


def holds_python(directory):
    return any(name.endswith(".py") for _, _, files in os.walk(directory) for name in files)


# Every directory that must mirror the repository: neither a split package nor
# inside one, and holding Python (a directory of fixture data mirrors nothing)
def discover_mirror_directories(suite_dirs = SUITE_DIRS):
    found = []
    for root, dirs in walk_directories(suite_dirs):
        dirs[:] = [name for name in dirs if not name.startswith("test_")]
        found.extend(os.path.join(root, name) for name in dirs if holds_python(os.path.join(root, name)))
    return sorted(found)


def suite_of(path, suite_dirs = SUITE_DIRS):
    return next(suite for suite in suite_dirs if path.startswith(suite + os.sep))


SPLIT_PACKAGES = discover_split_packages()
SPLIT_PACKAGE_IDS = [os.path.relpath(path, TESTS_DIR) for path in SPLIT_PACKAGES]
MIRROR_DIRECTORIES = discover_mirror_directories()
MIRROR_DIRECTORY_IDS = [os.path.relpath(path, TESTS_DIR) for path in MIRROR_DIRECTORIES]


def python_files(directory):
    return sorted(name for name in os.listdir(directory)
                  if name.endswith(".py") and os.path.isfile(os.path.join(directory, name)))


def is_test_module_name(name):
    return name.startswith("test_") and name.endswith(".py")


def defines_tests(path):
    return any(
        (isinstance(node, FUNCTION_DEFS) and node.name.startswith("test_"))
        or (isinstance(node, ast.ClassDef) and node.name.startswith("Test"))
        for node in parsed(path).body)


# Files that define tests but are not named test_*.py, so pytest skips them
def uncollected_test_files(directory):
    return [name for name in python_files(directory)
            if name not in SUPPORT_FILES and not is_test_module_name(name) and defines_tests(os.path.join(directory, name))]


# Where the code a split package covers would live: <repo>/<path>/<name>.py,
# .sh, or a package directory
def source_candidates(package, suite_dir = None, repo_root = REPO_ROOT):
    relative_parts = os.path.relpath(package, suite_dir or suite_of(package)).split(os.sep)
    base = os.path.join(repo_root, *relative_parts[:-1], relative_parts[-1][len("test_"):])
    return [base + extension for extension in SOURCE_EXTENSIONS] + [base]


# The repository directories a test directory may mirror; a hidden one, such
# as .githooks, is mirrored without its dot
def mirror_targets(directory, suite_dir = None, repo_root = REPO_ROOT):
    relative_path = os.path.relpath(directory, suite_dir or suite_of(directory))
    return [os.path.join(repo_root, relative_path), os.path.join(repo_root, "." + relative_path)]


def single_file_twin(package):
    twin = package + ".py"
    return twin if os.path.exists(twin) else None


@pytest.mark.parametrize("package", SPLIT_PACKAGES, ids = SPLIT_PACKAGE_IDS)
def test_a_split_package_holds_test_modules(package):
    assert any(is_test_module_name(name) for name in python_files(package)), "no test_<area>.py files inside"


@pytest.mark.parametrize("package", SPLIT_PACKAGES, ids = SPLIT_PACKAGE_IDS)
def test_a_split_package_has_no_uncollected_tests(package):
    uncollected = uncollected_test_files(package)

    assert not uncollected, f"tests outside a test_*.py file are never collected: {uncollected}"


@pytest.mark.parametrize("package", SPLIT_PACKAGES, ids = SPLIT_PACKAGE_IDS)
def test_a_split_package_covers_a_real_module(package):
    candidates = source_candidates(package)

    assert any(os.path.exists(path) for path in candidates), (
        "no source to mirror; expected one of " + ", ".join(os.path.relpath(path, REPO_ROOT) for path in candidates))


@pytest.mark.parametrize("package", SPLIT_PACKAGES, ids = SPLIT_PACKAGE_IDS)
def test_a_split_package_has_no_single_file_twin(package):
    twin = single_file_twin(package)

    assert twin is None, f"{os.path.basename(twin)} and {os.path.basename(package)}/ both exist"


@pytest.mark.parametrize("directory", MIRROR_DIRECTORIES, ids = MIRROR_DIRECTORY_IDS)
def test_a_test_directory_is_a_split_package_or_mirrors_the_repo(directory):
    relative_path = os.path.relpath(directory, TESTS_DIR)
    mirrors = relative_path in NON_MIRROR_DIRECTORIES or any(os.path.isdir(path) for path in mirror_targets(directory))

    assert mirrors, (
        f"'{relative_path}' mirrors nothing in the repository; if it is a split of "
        f"test_{os.path.basename(relative_path)}.py, name it test_{os.path.basename(relative_path)}/")

###########################################################
# The checks themselves
###########################################################

def write_file(path, text = ""):
    path.parent.mkdir(parents = True, exist_ok = True)
    path.write_text(text, encoding = "utf-8")


def test_split_packages_are_found_at_any_depth_but_not_in_caches(tmp_path):
    write_file(tmp_path / "unit" / "Shared" / "test_foo" / "test_a.py")
    write_file(tmp_path / "unit" / "Shared" / "helpers" / "x.py")
    write_file(tmp_path / "unit" / "Shared" / "__pycache__" / "test_cached" / "y.py")

    assert discover_split_packages(str(tmp_path)) == [str(tmp_path / "unit" / "Shared" / "test_foo")]


def test_misnamed_test_files_are_flagged(tmp_path):
    package = tmp_path / "test_foo"
    write_file(package / "conftest.py", "def test_in_conftest(): pass\n")
    write_file(package / "test_ok.py", "def test_x(): pass\n")
    write_file(package / "foo_tests.py", "def test_y(): pass\n")
    write_file(package / "cases.py", "class TestCases:\n    pass\n")
    write_file(package / "foo_helpers.py", "def build(): pass\n")

    assert uncollected_test_files(str(package)) == ["cases.py", "foo_tests.py"]


def test_a_split_package_maps_to_a_module_a_script_or_a_package(tmp_path):
    suite_dir = str(tmp_path / "unit")
    package = os.path.join(suite_dir, "Shared", "joybox", "test_amazon")
    base = os.path.join(str(tmp_path), "Shared", "joybox", "amazon")

    assert source_candidates(package, suite_dir, str(tmp_path)) == [base + ".py", base + ".sh", base]


def test_mirror_discovery_skips_split_packages_and_data_directories(tmp_path):
    for path in ("Shared/joybox/stores/a.py", "Shared/test_helm/sub/b.py", "meta/c.py", "Shared/fixtures/data.txt"):
        write_file(tmp_path / path)

    found = [os.path.relpath(path, str(tmp_path)) for path in discover_mirror_directories(str(tmp_path))]

    assert found == ["Shared", os.path.join("Shared", "joybox"), os.path.join("Shared", "joybox", "stores"), "meta"]


def test_a_hidden_directory_is_mirrored_without_its_dot(tmp_path):
    suite_dir = str(tmp_path / "unit")

    assert mirror_targets(os.path.join(suite_dir, "githooks"), suite_dir, str(tmp_path)) == [
        os.path.join(str(tmp_path), "githooks"), os.path.join(str(tmp_path), ".githooks")]


def test_a_single_file_twin_is_found(tmp_path):
    package = tmp_path / "test_foo"
    package.mkdir()
    assert single_file_twin(str(package)) is None

    write_file(tmp_path / "test_foo.py")
    assert single_file_twin(str(package)) == str(tmp_path / "test_foo.py")
