# Imports
import ast
import functools
import os

###########################################################
# The suites under test
#
# The meta tests read every file under Tests/unit and Tests/integration and
# hold it to one standard. They only parse; nothing here imports a test.
###########################################################

TESTS_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO_ROOT = os.path.dirname(TESTS_DIR)
SHARED_DIR = os.path.join(REPO_ROOT, "Shared")
SUITE_DIRS = (os.path.join(TESTS_DIR, "unit"), os.path.join(TESTS_DIR, "integration"))

FUNCTION_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)


# Every test_*.py under the suites, or with test_modules_only off every .py
def discover_python_files(test_modules_only, suite_dirs = SUITE_DIRS):
    found = []
    for suite_dir in suite_dirs:
        for root, dirs, files in os.walk(suite_dir):
            dirs[:] = [name for name in dirs if name != "__pycache__"]
            for name in files:
                if name.endswith(".py") and (not test_modules_only or name.startswith("test_")):
                    found.append(os.path.join(root, name))
    return sorted(found)


# A path relative to Tests/, such as unit/Shared/joybox/test_strings.py
def relative(path):
    return os.path.relpath(path, TESTS_DIR)


TEST_FILES = discover_python_files(test_modules_only = True)
ALL_FILES = discover_python_files(test_modules_only = False)
TEST_IDS = [relative(path) for path in TEST_FILES]
ALL_IDS = [relative(path) for path in ALL_FILES]


@functools.lru_cache(maxsize = None)
def parsed(path):
    with open(path, "r", encoding = "utf-8") as handle:
        return ast.parse(handle.read())


# The syntax tree of text, written to a throwaway test module under tmp_path
def parse_sample(tmp_path, text, name = "test_sample.py"):
    path = tmp_path / name
    path.write_text(text, encoding = "utf-8")
    return ast.parse(text)


def is_test_function(node):
    return isinstance(node, FUNCTION_DEFS) and node.name.startswith("test_")


# Every test pytest would collect: module level, or a method of a Test class
def collected_tests(tree):
    found = [node for node in tree.body if is_test_function(node)]
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            found.extend(member for member in node.body if is_test_function(member))
    return found


def parameter_names(function):
    arguments = function.args
    return [argument.arg for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs]


def is_fixture(function):
    return any("fixture" in ast.unparse(decorator) for decorator in function.decorator_list)

###########################################################
# Checks
#
# What makes a test fail when its expectation is not met: an assert, a mock's
# or recorder's assert_*, pytest.fail, a pytest.raises / warns block, or a
# call to a helper that itself makes checks. Helpers are often imported by
# name from a *_helpers.py beside the test, so those are followed too.
###########################################################

def is_raises_block(node):
    return isinstance(node, ast.With) and any(
        any(word in ast.unparse(item.context_expr) for word in ("raises", "warns"))
        for item in node.items)


def is_check_call(node, checkers = frozenset()):
    if not isinstance(node, ast.Call):
        return False
    name = ast.unparse(node.func)
    last = name.rsplit(".", maxsplit = 1)[-1]
    return last.startswith("assert") or name.endswith("pytest.fail") or last in checkers


# Checks reachable in statements without entering a node of a type in stop_at.
# A try/finally with no handler runs its body straight through, so it is not a branch.
def checks_in(statements, stop_at = (), checkers = frozenset()):
    found = []

    def visit(node):
        if isinstance(node, stop_at) and not (isinstance(node, ast.Try) and not node.handlers):
            return
        if isinstance(node, ast.Assert) or is_check_call(node, checkers) or is_raises_block(node):
            found.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child)
    for statement in statements:
        visit(statement)
    return found


# Where a module imported by name from path lives: beside it, in a directory
# above it within Tests, or at the top of Tests
def find_helper_module(path, module_name):
    directory = os.path.dirname(path)
    while True:
        candidate = os.path.join(directory, module_name.replace(".", os.sep) + ".py")
        if os.path.isfile(candidate):
            return candidate
        if directory == TESTS_DIR or not directory.startswith(TESTS_DIR):
            return None
        directory = os.path.dirname(directory)


# Names of the functions defined in tree that make checks, directly or through
# another such function, given the checker names it can already see
def local_checkers(tree, known = frozenset()):
    functions = [node for node in ast.walk(tree) if isinstance(node, FUNCTION_DEFS) and not node.name.startswith("test_")]
    checkers = set()
    while True:
        visible = frozenset(known | checkers)
        found = {function.name for function in functions if checks_in(function.body, (), visible)}
        if found <= checkers:
            return frozenset(checkers)
        checkers |= found


# Every name a call in path can use to reach a checking helper
@functools.lru_cache(maxsize = None)
def checker_names(path, seen = frozenset()):
    tree = parsed(path)
    imported = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            helper = find_helper_module(path, node.module)
            if helper and helper not in seen:
                theirs = checker_names(helper, seen | {path})
                imported.update(alias.asname or alias.name for alias in node.names if alias.name in theirs)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                helper = find_helper_module(path, alias.name)
                if helper and helper not in seen:
                    imported.update(checker_names(helper, seen | {path}))
    return local_checkers(tree, frozenset(imported)) | frozenset(imported)
