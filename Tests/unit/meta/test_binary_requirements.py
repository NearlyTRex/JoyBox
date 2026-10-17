# Imports
import ast
import os

# Third-party imports
import pytest

# Local imports
from meta_helpers import (
    FUNCTION_DEFS, TESTS_DIR, TEST_FILES, TEST_IDS, is_fixture, parameter_names, parse_sample, parsed, relative)


###########################################################
# Required programs
#
# A test that needs a program outside the process declares it with
# requires_binary (on PATH) or requires_tool (from the JoyBox tool registry),
# at module, class or test level; see Tests/conftest.py. The markers are
# enforced at collection, so a machine without the program skips the test
# before any fixture starts, and the requirement is readable in one place
# rather than buried in a test body. A requirement that is only enforced at
# run time, or not declared at all, fails here instead of failing, or
# silently skipping, on someone else's machine.
###########################################################

MARKERS = ("requires_binary", "requires_tool")

# Fixtures that need programs, and which. A test using one, directly or
# through a fixture that uses it, must declare them.
FIXTURE_BINARIES = {
    "shell_sandbox": {"bash", "unshare"},
    "shell_traced_env": {"bash"},
}

SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen"}


# requires_binary(...) or requires_tool(...) marker calls within nodes
def marker_calls(nodes, marker):
    return [
        node for top in nodes for node in ast.walk(top)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == marker]


def marked_names(nodes, marker = "requires_binary"):
    return {
        argument.value for call in marker_calls(nodes, marker) for argument in call.args
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str)}


# Each name an "a|b" requirement accepts
def accepted(names):
    return {option for name in names for option in name.split("|")}


def module_marks(tree):
    return [
        node.value for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets)]


def declared_anywhere(tree, marker = "requires_binary"):
    decorators = [
        decorator for node in ast.walk(tree) if isinstance(node, FUNCTION_DEFS + (ast.ClassDef,))
        for decorator in node.decorator_list]
    return marked_names(module_marks(tree), marker) | marked_names(decorators, marker)


# (name, function, binaries declared for it at module, class or test level) per test
def declared_per_test(tree):
    module_level = marked_names(module_marks(tree))
    found = []
    for node in tree.body:
        if isinstance(node, FUNCTION_DEFS) and node.name.startswith("test_"):
            found.append((node.name, node, module_level | marked_names(node.decorator_list)))
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            class_level = module_level | marked_names(node.decorator_list)
            found.extend(
                ("%s.%s" % (node.name, member.name), member, class_level | marked_names(member.decorator_list))
                for member in node.body if isinstance(member, FUNCTION_DEFS) and member.name.startswith("test_"))
    return found


# The conftest.py files whose fixtures a test file can see
def visible_conftests(path):
    found = []
    directory = os.path.dirname(path)
    while directory.startswith(TESTS_DIR):
        conftest = os.path.join(directory, "conftest.py")
        if os.path.isfile(conftest) and conftest != path:
            found.append(conftest)
        directory = os.path.dirname(directory)
    return found


# The fixtures defined in trees, by name, with the fixtures each one requests
def fixture_parameters(trees):
    found = {}
    for tree in reversed(trees):
        for node in tree.body:
            if isinstance(node, FUNCTION_DEFS) and is_fixture(node):
                found[node.name] = set(parameter_names(node))
    return found


# The programs requesting these fixtures needs, through any depth of fixtures
def binaries_needed(requested, fixtures):
    needed, seen, pending = set(), set(), list(requested)
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        needed |= FIXTURE_BINARIES.get(name, set())
        pending.extend(fixtures.get(name, ()))
    return needed


# Whether a call searches this machine's PATH: shutil.which(...) or which(...)
def is_host_lookup(node):
    if not isinstance(node, ast.Call):
        return False
    function = node.func
    if isinstance(function, ast.Name):
        return function.id == "which"
    return (isinstance(function, ast.Attribute) and function.attr == "which"
            and isinstance(function.value, ast.Name) and function.value.id == "shutil")


def calls_skip(statements):
    return any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "skip"
        for statement in statements for node in ast.walk(statement))


# Lines where a requirement is enforced at run time rather than by a marker: a
# function taking a requires_* fixture, a which() check that skips, or a skipif
# whose condition looks up a program
def imperative_gates(tree):
    looked_up = {
        target.id for node in tree.body if isinstance(node, ast.Assign)
        and any(is_host_lookup(sub) for sub in ast.walk(node.value))
        for target in node.targets if isinstance(target, ast.Name)}
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, FUNCTION_DEFS) and set(parameter_names(node)) & set(MARKERS):
            lines.append(node.lineno)
        elif isinstance(node, ast.If) and any(is_host_lookup(sub) for sub in ast.walk(node.test)) and calls_skip(node.body):
            lines.append(node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "skipif":
            condition = list(ast.walk(node.args[0])) if node.args else []
            if any(is_host_lookup(sub) or (isinstance(sub, ast.Name) and sub.id in looked_up) for sub in condition):
                lines.append(node.lineno)
    return sorted(set(lines))


def is_subprocess_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in SUBPROCESS_CALLS
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess")


# Programs run for real through subprocess.<call>([<literal>, ...])
def subprocess_binaries(tree):
    found = set()
    for node in ast.walk(tree):
        if is_subprocess_call(node) and node.args and isinstance(node.args[0], ast.List) and node.args[0].elts:
            first = node.args[0].elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.add(first.value)
    return found


# Whether the tests start this interpreter in a subprocess, which is a program
# outside the process that is always there to run
def runs_the_interpreter(tree):
    return any(
        is_subprocess_call(node) and node.args and isinstance(node.args[0], ast.List) and node.args[0].elts
        and ast.unparse(node.args[0].elts[0]) == "sys.executable"
        for node in ast.walk(tree))


INTEGRATION_FILES = [path for path in TEST_FILES if relative(path).startswith("integration" + os.sep)]


def test_test_files_were_discovered():
    assert any(path.startswith("unit") for path in TEST_IDS)
    assert INTEGRATION_FILES


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_program_is_required_imperatively(path):
    # A requirement checked inside a test or fixture runs after the test's
    # other fixtures have already started; the marker skips before any do.
    lines = imperative_gates(parsed(path))

    assert not lines, (
        f"{relative(path)} checks for a program at run time (line(s) {lines}); "
        "declare it with pytest.mark.requires_binary(...) or requires_tool(...) instead")


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_requirement_markers_name_programs_literally(path):
    # A computed name can't be checked here or named in the skip reason.
    bad = []
    for marker in MARKERS:
        for call in marker_calls([parsed(path)], marker):
            literal = all(isinstance(argument, ast.Constant) and isinstance(argument.value, str) for argument in call.args)
            if not call.args or not literal or call.keywords:
                bad.append(call.lineno)

    assert not bad, f"{relative(path)}: requires_binary and requires_tool take string literals (line(s) {sorted(bad)})"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_tests_using_a_program_fixture_declare_its_programs(path):
    tree = parsed(path)
    fixtures = fixture_parameters([tree] + [parsed(conftest) for conftest in visible_conftests(path)])
    missing = []
    for name, function, declared in declared_per_test(tree):
        needed = binaries_needed(parameter_names(function), fixtures)
        if not needed <= accepted(declared):
            missing.append("%s needs %s" % (name, sorted(needed - accepted(declared))))

    assert not missing, f"{relative(path)}: " + "; ".join(missing)


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_programs_run_through_subprocess_are_declared(path):
    tree = parsed(path)
    undeclared = subprocess_binaries(tree) - accepted(declared_anywhere(tree))

    assert not undeclared, (
        f"{relative(path)} runs {sorted(undeclared)} but never declares it with pytest.mark.requires_binary(...)")


@pytest.mark.parametrize("path", INTEGRATION_FILES, ids = [relative(path) for path in INTEGRATION_FILES])
def test_an_integration_file_declares_the_programs_it_needs(path):
    # Integration tests are the ones that need a program outside the process;
    # one that needs none belongs in unit/.
    tree = parsed(path)

    assert declared_anywhere(tree) or declared_anywhere(tree, "requires_tool") or runs_the_interpreter(tree), (
        f"{relative(path)} declares no program; mark what it runs, or move it to unit/ if it runs none")

###########################################################
# The checks themselves
###########################################################

def test_markers_are_read_at_module_class_and_test_level(tmp_path):
    tree = parse_sample(tmp_path, (
        "import pytest\n"
        "pytestmark = pytest.mark.requires_binary('git')\n"
        "@pytest.mark.requires_binary('docker')\n"
        "class TestA:\n"
        "    @pytest.mark.requires_binary('gpg')\n"
        "    def test_one(self): pass\n"
        "    def test_two(self): pass\n"
        "def test_three(): pass\n"))

    assert {name: declared for name, _, declared in declared_per_test(tree)} == {
        "TestA.test_one": {"git", "docker", "gpg"}, "TestA.test_two": {"git", "docker"}, "test_three": {"git"}}
    assert declared_anywhere(tree) == {"git", "docker", "gpg"}


def test_tools_are_read_apart_from_binaries(tmp_path):
    tree = parse_sample(tmp_path, "import pytest\npytestmark = [pytest.mark.requires_tool('XorrISO'), pytest.mark.slow]\n")

    assert declared_anywhere(tree, "requires_tool") == {"XorrISO"}
    assert declared_anywhere(tree) == set()


def test_either_of_two_programs_satisfies_a_need():
    assert accepted({"xorriso|mkisofs", "gpg"}) == {"xorriso", "mkisofs", "gpg"}


def test_a_program_fixture_is_found_through_other_fixtures(tmp_path):
    tree = parse_sample(tmp_path, (
        "import pytest\n"
        "@pytest.fixture\ndef server(shell_sandbox):\n    return shell_sandbox\n"
        "@pytest.fixture\ndef wired(server, tmp_path):\n    return server\n"))

    assert binaries_needed(["wired"], fixture_parameters([tree])) == {"bash", "unshare"}
    assert binaries_needed(["tmp_path"], fixture_parameters([tree])) == set()


def test_a_nearer_fixture_replaces_a_conftest_one(tmp_path):
    near = parse_sample(tmp_path, "import pytest\n@pytest.fixture\ndef server(tmp_path):\n    return tmp_path\n")
    far = parse_sample(tmp_path, "import pytest\n@pytest.fixture\ndef server(shell_sandbox):\n    return 1\n", "conftest.py")

    assert binaries_needed(["server"], fixture_parameters([near, far])) == set()


@pytest.mark.parametrize("source, lines", [
    ("def test_a(requires_tool):\n    pass\n", [1]),
    ("import shutil, pytest\ndef test_a():\n    if not shutil.which('git'):\n        pytest.skip('no git')\n", [3]),
    ("import shutil\ndef test_a():\n    if shutil.which('git'):\n        pass\n", []),
    ("import shutil, pytest\nHAS = shutil.which('docker') is not None\n@pytest.mark.skipif(not HAS, reason = 'x')\ndef test_a(): pass\n", [3]),
    ("import pytest\n@pytest.mark.skipif(IS_WINDOWS, reason = 'x')\ndef test_a(): pass\n", []),
    ("import pytest\ndef test_a(cmd):\n    if not cmd.which('unzip'):\n        pytest.skip('not here')\n", []),
])
def test_imperative_gates_are_found(tmp_path, source, lines):
    assert imperative_gates(parse_sample(tmp_path, source)) == lines


@pytest.mark.parametrize("source, runs", [
    ("import subprocess, sys\ndef test_a():\n    subprocess.run([sys.executable, '-m', 'x'])\n", True),
    ("import subprocess\ndef test_a(python):\n    subprocess.run([python, '-m', 'x'])\n", False),
    ("import sys\ndef test_a():\n    assert sys.executable\n", False),
])
def test_a_subprocess_of_this_interpreter_is_recognised(tmp_path, source, runs):
    assert runs_the_interpreter(parse_sample(tmp_path, source)) is runs


def test_only_literal_subprocess_programs_are_collected(tmp_path):
    tree = parse_sample(tmp_path, (
        "import subprocess\n"
        "def test_a(args):\n"
        "    subprocess.run(['git', 'init'])\n"
        "    subprocess.check_output(['docker', *args])\n"
        "    subprocess.run(args)\n"
        "    other.run(['tilt'])\n"))

    assert subprocess_binaries(tree) == {"git", "docker"}
