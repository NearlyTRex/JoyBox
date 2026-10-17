# Imports
import os
import subprocess
import sys

# Local imports
from meta_helpers import ALL_FILES, REPO_ROOT, SHARED_DIR, SUITE_DIRS, TESTS_DIR


###########################################################
# Pylint
#
# Pylint runs over every test file with Tests/pylintrc, and any message fails.
# The rcfile only turns off rules that do not suit tests and the repository's
# own conventions; everything else, such as unused variables, undefined
# names, calls that do not match a signature and files opened without an
# encoding, is enforced.
###########################################################

RCFILE = os.path.join(TESTS_DIR, "pylintrc")

# The library is linted by ruff, which has no stable rule for this yet: a text
# file opened without an encoding takes Windows' code page there
LIBRARY_TARGETS = [SHARED_DIR, os.path.join(REPO_ROOT, "Scripts")]
LIBRARY_RULES = ["unspecified-encoding"]
TARGETS = list(SUITE_DIRS) + [
    os.path.join(TESTS_DIR, name) for name in sorted(os.listdir(TESTS_DIR)) if name.endswith(".py")]


# Tests import the helpers beside them by name, through each conftest's
# sys.path entry, which pylint has to be told about
def import_roots():
    roots = {TESTS_DIR}
    roots.update(os.path.dirname(path) for path in ALL_FILES if os.path.basename(path) == "conftest.py")
    return sorted(roots)


def run_pylint(*arguments):
    env = dict(os.environ, PYTHONPATH = os.pathsep.join(import_roots()))
    return subprocess.run(
        [sys.executable, "-m", "pylint", "--rcfile=" + RCFILE, "--score=no", *arguments],
        cwd = REPO_ROOT, env = env, capture_output = True, text = True, check = False)


def test_pylint_reports_a_finding_it_is_given(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("import os\n", encoding = "utf-8")

    result = run_pylint(str(sample))

    assert result.returncode != 0
    assert "unused-import" in result.stdout


def test_every_split_package_is_an_import_root():
    assert os.path.join(TESTS_DIR, "unit", "meta") in import_roots()
    assert TESTS_DIR in import_roots()


def test_pylint_is_clean_over_all_tests():
    result = run_pylint(*TARGETS)

    assert result.returncode == 0, result.stdout + result.stderr


def test_the_library_names_the_encoding_of_every_text_file():
    result = run_pylint("--disable=all", "--enable=" + ",".join(LIBRARY_RULES), *LIBRARY_TARGETS)

    assert result.returncode == 0, result.stdout + result.stderr


def test_the_library_rules_report_a_finding_they_are_given(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("with open('x') as handle:\n    handle.read()\n", encoding = "utf-8")

    result = run_pylint("--disable=all", "--enable=" + ",".join(LIBRARY_RULES), str(sample))

    assert result.returncode != 0
    assert "unspecified-encoding" in result.stdout
