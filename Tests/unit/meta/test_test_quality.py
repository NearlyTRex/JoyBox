# Imports
import ast
import collections
import hashlib

# Third-party imports
import pytest

# Local imports
import meta_helpers
from meta_helpers import (
    ALL_FILES, ALL_IDS, FUNCTION_DEFS, TEST_FILES, TEST_IDS, checker_names, checks_in, collected_tests,
    local_checkers, parse_sample, parsed, relative)


###########################################################
# Test quality
#
# A test that cannot fail reads as coverage and protects nothing. These catch
# the shapes that let a test pass whatever the code does: asserting nothing,
# asserting only inside a branch that may not run, swallowing the exception it
# exists to see, an assertion true by construction, checking only that a value
# exists or has a type, and a helper pasted into several files that then drift
# apart. There are no exemption lists: a test that trips one is fixed.
###########################################################

CONDITIONAL = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try)


def has_any_check(function, checkers = frozenset()):
    return bool(checks_in(function.body, (), checkers))


# A check that runs whenever the test does: not inside a branch, loop or try
def has_unconditional_check(function, checkers = frozenset()):
    return bool(checks_in(function.body, CONDITIONAL, checkers))


# Lines of except handlers whose whole body is pass (or a bare string)
def swallowed_handlers(tree):
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                body = [statement for statement in handler.body
                        if not (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant))]
                if all(isinstance(statement, ast.Pass) for statement in body):
                    lines.append(handler.lineno)
    return sorted(lines)


# Why an assertion cannot fail, or None
def tautology(assertion):
    test = assertion.test
    if isinstance(test, ast.Constant) and test.value:
        return "a constant that is always true"
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.Eq, ast.Is)):
        left, right = test.left, test.comparators[0]
        if ast.unparse(left) == ast.unparse(right):
            return "compares a value with itself"
        if isinstance(right, ast.BoolOp) and isinstance(right.op, ast.Or) and ast.unparse(right.values[0]) == ast.unparse(left):
            return "compares a value with itself or a fallback"
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        if any(isinstance(value, ast.Constant) and value.value for value in test.values):
            return "has an or branch that is always true"
    return None


# An assert that only says a value exists or has a type
def is_weak_assertion(assertion):
    test = assertion.test
    if isinstance(test, ast.Call):
        return ast.unparse(test.func) == "isinstance"
    return (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.IsNot)
            and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None)


# Tests whose only checks are weak, so they pass for almost any value
def weak_only_tests(tree, checkers = frozenset()):
    weak = []
    for function in collected_tests(tree):
        checks = checks_in(function.body, (), checkers)
        if checks and all(isinstance(check, ast.Assert) and is_weak_assertion(check) for check in checks):
            weak.append("%s (line %d)" % (function.name, function.lineno))
    return weak


# Lines that build a raising callable as (_ for _ in ()).throw(...), which
# reads as a puzzle; a def that raises says the same thing
def generator_throws(tree):
    return sorted(
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "throw"
        and isinstance(node.func.value, ast.GeneratorExp))


# (name, source) of every module level function that is not a test. The source
# includes the module constants it reads, so the same function over a
# different table is not mistaken for a copy.
def module_helpers(tree):
    constants = {
        target.id: ast.unparse(node) for node in tree.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)}
    found = []
    for node in tree.body:
        if isinstance(node, FUNCTION_DEFS) and not node.name.startswith("test_") and not node.name.startswith("__"):
            names = sorted({name.id for name in ast.walk(node) if isinstance(name, ast.Name)})
            found.append((node.name, ast.unparse(node) + "".join("\n" + constants[name] for name in names if name in constants)))
    return found


def label(function):
    return "%s (line %d)" % (function.name, function.lineno)


def test_files_and_helpers_were_discovered():
    assert len(TEST_FILES) > 500
    assert len(ALL_FILES) > len(TEST_FILES)


@pytest.mark.parametrize("path", ALL_FILES, ids = ALL_IDS)
def test_no_exception_is_silently_swallowed(path):
    # except X: pass around a test's steps hides the failure the test exists
    # to catch; expect it with pytest.raises, or assert on what handling it did.
    lines = swallowed_handlers(parsed(path))

    assert not lines, f"{relative(path)}: except handler that does nothing, line(s) {lines}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_every_test_checks_something(path):
    # A test that only calls the code passes unless the code raises, whatever
    # it returns or does.
    checkers = checker_names(path)
    unchecked = [label(function) for function in collected_tests(parsed(path)) if not has_any_check(function, checkers)]

    assert not unchecked, f"{relative(path)}: asserts nothing: {unchecked}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_every_test_has_a_check_that_always_runs(path):
    # Checks only inside an if, a loop or a try may never execute (an empty
    # list, a branch not taken, an exception raised first) and the test passes.
    checkers = checker_names(path)
    conditional = [
        label(function) for function in collected_tests(parsed(path))
        if has_any_check(function, checkers) and not has_unconditional_check(function, checkers)]

    assert not conditional, f"{relative(path)}: every check is conditional: {conditional}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_assertion_is_true_by_construction(path):
    found = [
        "%s line %d: %s" % (function.name, node.lineno, tautology(node))
        for function in collected_tests(parsed(path)) for node in ast.walk(function)
        if isinstance(node, ast.Assert) and tautology(node)]

    assert not found, f"{relative(path)}: {found}"


@pytest.mark.parametrize("path", TEST_FILES, ids = TEST_IDS)
def test_no_test_only_checks_that_a_value_exists_or_has_a_type(path):
    # is not None and isinstance pass for nearly any value; assert what it is.
    weak = weak_only_tests(parsed(path), checker_names(path))

    assert not weak, f"{relative(path)}: only checks existence or type: {weak}"


@pytest.mark.parametrize("path", ALL_FILES, ids = ALL_IDS)
def test_no_raising_callable_is_built_from_a_generator(path):
    lines = generator_throws(parsed(path))

    assert not lines, f"{relative(path)}: define a function that raises instead, line(s) {lines}"


# (name, files) for each helper whose identical source is in several files;
# two different helpers sharing a name are reported apart
def copied_helpers(sources_by_file):
    where = collections.defaultdict(set)
    for path, helpers in sources_by_file.items():
        for name, source in helpers:
            where[(name, hashlib.sha256(source.encode()).hexdigest())].add(path)
    return sorted((name, sorted(files)) for (name, _), files in where.items() if len(files) > 1)


def test_no_helper_is_copied_between_files():
    # A helper pasted into several files is fixed in one and left broken in
    # the rest. Share it from the nearest conftest.py or a *_helpers.py.
    copied = copied_helpers({relative(path): module_helpers(parsed(path)) for path in ALL_FILES})

    assert not copied, f"identical helper defined in several files: {copied}"

###########################################################
# The checks themselves
#
# They only guard anything if they can fail, so each is run against a source
# that breaks exactly one rule.
###########################################################

def only_test(tmp_path, body):
    return collected_tests(parse_sample(tmp_path, "def test_x(mock):\n" + body))[0]


def test_a_bare_call_checks_nothing(tmp_path):
    assert not has_any_check(only_test(tmp_path, "    run()\n"))


@pytest.mark.parametrize("body", [
    "    assert run()\n",
    "    mock.assert_called_once_with(1)\n",
    "    pytest.fail('no')\n",
    "    with pytest.raises(ValueError):\n        run()\n",
])
def test_asserts_mock_checks_fails_and_raises_blocks_count(tmp_path, body):
    assert has_unconditional_check(only_test(tmp_path, body))


@pytest.mark.parametrize("body", [
    "    if ok:\n        assert run()\n",
    "    for x in xs:\n        assert x\n",
    "    try:\n        run()\n    except ValueError:\n        assert False\n",
])
def test_a_check_inside_a_branch_loop_or_try_is_conditional(tmp_path, body):
    function = only_test(tmp_path, body)

    assert has_any_check(function)
    assert not has_unconditional_check(function)


def test_a_try_finally_without_a_handler_is_not_a_branch(tmp_path):
    assert has_unconditional_check(only_test(tmp_path, "    try:\n        assert run()\n    finally:\n        undo()\n"))


def test_a_check_beside_a_branch_still_runs(tmp_path):
    assert has_unconditional_check(only_test(tmp_path, "    if ok:\n        pass\n    assert run()\n"))


def test_a_helper_that_checks_counts_through_any_depth(tmp_path):
    tree = parse_sample(tmp_path, (
        "def check(x):\n    assert x\n"
        "def check_twice(x):\n    check(x)\n    check(x)\n"
        "def plain(x):\n    return x\n"))

    assert local_checkers(tree) == {"check", "check_twice"}


def test_a_checking_helper_imported_from_a_sibling_module_counts(tmp_path, monkeypatch):
    (tmp_path / "sample_helpers.py").write_text("def check_run(seams):\n    assert seams.ran\n", encoding = "utf-8")
    (tmp_path / "test_sample.py").write_text(
        "from sample_helpers import check_run as verify\ndef test_x(seams):\n    verify(seams)\n", encoding = "utf-8")
    module = str(tmp_path / "test_sample.py")
    monkeypatch.setattr(meta_helpers, "TESTS_DIR", str(tmp_path))

    checkers = meta_helpers.checker_names(module)

    assert "verify" in checkers
    assert has_unconditional_check(collected_tests(parsed(module))[0], checkers)


def test_a_handler_that_only_passes_is_a_swallow(tmp_path):
    tree = parse_sample(tmp_path, (
        "def a():\n    try:\n        run()\n    except ValueError:\n        pass\n"
        "def b():\n    try:\n        run()\n    except ValueError:\n        return None\n"
        "def c():\n    try:\n        run()\n    except ValueError as error:\n        log(error)\n"))

    assert swallowed_handlers(tree) == [4]


@pytest.mark.parametrize("expression, cannot_fail", [
    ("True", True),
    ("cmd[0] == cmd[0]", True),
    ("value is value", True),
    ("op.path == (op.path or 'x')", True),
    ("result or True", True),
    ("cmd[0] == (op.path or 'x')", False),
    ("result == 3", False),
    ("not result", False),
])
def test_tautologies_are_recognised(expression, cannot_fail):
    assert bool(tautology(ast.parse("assert " + expression).body[0])) is cannot_fail


@pytest.mark.parametrize("body, weak", [
    ("    assert run() is not None\n", True),
    ("    assert isinstance(run(), dict)\n", True),
    ("    assert run() is not None\n    assert isinstance(run(), dict)\n", True),
    ("    assert run() == 1\n", False),
    ("    assert run() is not None\n    mock.assert_called_once()\n", False),
    ("    assert isinstance(run(), dict)\n    with pytest.raises(ValueError):\n        run()\n", False),
])
def test_only_existence_or_type_checks_are_weak(tmp_path, body, weak):
    assert bool(weak_only_tests(parse_sample(tmp_path, "def test_x(mock):\n" + body))) is weak


def test_a_generator_throw_is_found_and_a_raising_function_is_not(tmp_path):
    found = parse_sample(tmp_path, "f = lambda: (_ for _ in ()).throw(ValueError('x'))\n")
    clean = parse_sample(tmp_path, "def f():\n    raise ValueError('x')\ng = gen.throw(ValueError('x'))\n")

    assert generator_throws(found) == [1]
    assert generator_throws(clean) == []


def test_identical_helpers_are_matched_by_source_and_tests_are_not_helpers(tmp_path):
    one = module_helpers(parse_sample(tmp_path, "def run(a):\n    return a\ndef test_x():\n    pass\n"))
    two = module_helpers(parse_sample(tmp_path, "def run(a):\n    return a\n"))
    other = module_helpers(parse_sample(tmp_path, "def run(a, b):\n    return a\n"))

    assert one == two
    assert one != other
    assert [name for name, _ in one] == ["run"]


def test_two_sets_of_copies_sharing_a_name_are_both_reported():
    one = [("write", "def write(): return 1")]
    two = [("write", "def write(): return 2")]

    assert copied_helpers({"a.py": one, "b.py": one, "c.py": two, "d.py": two}) == [
        ("write", ["a.py", "b.py"]), ("write", ["c.py", "d.py"])]


def test_the_same_function_over_a_different_constant_is_not_a_copy(tmp_path):
    one = module_helpers(parse_sample(tmp_path, "KINDS = {'a': 1}\ndef kind(r):\n    return KINDS[r]\n"))
    other = module_helpers(parse_sample(tmp_path, "KINDS = {'b': 2}\ndef kind(r):\n    return KINDS[r]\n"))

    assert one != other
