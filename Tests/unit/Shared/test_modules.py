# Imports
import ast
import builtins
import re
import importlib
import inspect
import os
import warnings

# Third-party imports
import pytest


###########################################################
# Whole-tree sweeps
#
# Every module in Shared/joybox, checked for the failures that are cheap to
# catch everywhere and expensive to find one at a time: an import that breaks
# under a dependency change, a mutable default that accumulates between calls,
# and a shadowed builtin.
###########################################################

def discover_modules(shared_dir):
    found = []
    for dirpath, dirnames, filenames in os.walk(shared_dir):
        if "__pycache__" in dirpath:
            continue
        for filename in sorted(filenames):
            if not filename.endswith(".py") or filename == "__init__.py":
                continue
            path = os.path.join(dirpath, filename)
            relative = os.path.relpath(path, shared_dir)[:-3].replace(os.sep, ".")
            found.append(("joybox." + relative, path))
    return found


def _shared_dir():
    from conftest import SHARED_DIR
    return os.path.join(SHARED_DIR, "joybox")


MODULES = discover_modules(_shared_dir())
MODULE_IDS = [name for name, _ in MODULES]


def test_modules_were_discovered():
    assert len(MODULES) > 200, f"only found {len(MODULES)} modules"


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_every_module_imports(module_name, path):
    # A lazy import inside a function hides a broken dependency until the code
    # path runs; importing every module surfaces it now.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        importlib.import_module(module_name)


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_every_module_parses(module_name, path):
    with open(path, "r", encoding = "utf-8") as handle:
        ast.parse(handle.read())


###########################################################
# Mutable defaults
#
# A default list or dict is created once at definition time and shared by
# every call, so a function that mutates one accumulates state across calls.
###########################################################

def mutable_default_offenders(tree):
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        arguments = node.args
        defaults = list(arguments.defaults) + [
            default for default in arguments.kw_defaults if default is not None
        ]
        mutable_names = set()
        positional = arguments.posonlyargs + arguments.args
        paired = positional[len(positional) - len(arguments.defaults):] if arguments.defaults else []
        for argument, default in zip(paired, arguments.defaults):
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                mutable_names.add(argument.arg)
        if not mutable_names:
            continue

        # Only a mutated default is a problem; a read-only one is harmless.
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
                target = inner.func.value
                mutator = inner.func.attr in {
                    "append", "extend", "insert", "pop", "remove", "clear",
                    "update", "setdefault", "add", "sort",
                }
                if mutator and isinstance(target, ast.Name) and target.id in mutable_names:
                    offenders.append(f"{node.name}: {target.id}.{inner.func.attr}()")
            elif isinstance(inner, ast.Subscript) and isinstance(inner.ctx, ast.Store):
                target = inner.value
                if isinstance(target, ast.Name) and target.id in mutable_names:
                    offenders.append(f"{node.name}: {target.id}[...] = ...")
    return offenders


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_no_mutable_default_is_mutated(module_name, path):
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = mutable_default_offenders(tree)

    assert not offenders, f"{module_name} mutates a default argument: {offenders}"


###########################################################
# Shadowing
###########################################################

SHADOWABLE = {"list", "dict", "set", "str", "int", "type", "id", "file", "input", "filter", "map"}


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_no_module_level_name_shadows_a_builtin(module_name, path):
    # A module-level rebinding of a builtin affects every function in the file.
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in SHADOWABLE:
                    offenders.append(target.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in SHADOWABLE:
                offenders.append(node.name)

    assert not offenders, f"{module_name} shadows builtins at module level: {offenders}"


###########################################################
# Reachability
###########################################################

def unreachable_offenders(tree):
    offenders = []
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        for index, statement in enumerate(body[:-1]):
            if isinstance(statement, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                offenders.append(
                    "line %d after %s" % (body[index + 1].lineno, type(statement).__name__))
                break
    return offenders


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_no_statement_is_unreachable(module_name, path):
    # An early return above further logic silently drops it, and any names that
    # logic reads are never bound.
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = unreachable_offenders(tree)

    assert not offenders, f"{module_name} has unreachable statements: {offenders}"


def bare_except_handlers(tree):
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if node.type is None:
            offenders.append("line %d" % node.lineno)
    return offenders


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_no_handler_catches_everything(module_name, path):
    # A bare except also swallows KeyboardInterrupt and SystemExit, so a run
    # cannot be interrupted and a deliberate exit inside the block is eaten.
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = bare_except_handlers(tree)

    assert not offenders, f"{module_name} catches everything at: {offenders}"


###########################################################
# Naming
###########################################################

SNAKE_CASE = re.compile(r"^_?[a-z][a-z0-9_]*$")


def non_snake_case_functions(tree):
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("__") and node.name.endswith("__"):
            continue
        if not SNAKE_CASE.match(node.name):
            offenders.append("line %d: %s" % (node.lineno, node.name))
    return offenders


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_every_function_is_snake_case(module_name, path):
    # The tree is snake_case throughout. A stray camelCase name is usually a
    # partly applied rename, and one of those reached into a string literal.
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = non_snake_case_functions(tree)

    assert not offenders, f"{module_name} has non snake_case functions: {offenders}"


###########################################################
# Name resolution
#
# A name that is read but never bound anywhere in its file raises NameError
# the first time that line runs. A partly applied rename leaves exactly this
# shape: the definition moves, the reference does not.
###########################################################

BUILTIN_NAMES = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__package__"}


def bound_names(tree):
    bound = set(BUILTIN_NAMES)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
    return bound


def unresolved_names(tree):
    bound = bound_names(tree)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in bound:
                offenders.append("line %d: %s" % (node.lineno, node.id))
    return offenders


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_every_name_resolves(module_name, path):
    # Deliberately generous: a name bound anywhere in the file counts, so this
    # only catches names with no binding at all.
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = unresolved_names(tree)

    assert not offenders, f"{module_name} reads names that are never bound: {offenders}"


###########################################################
# Attribute shadowing
###########################################################

def shadowing_offenders(tree):
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        methods = {sub.name: sub.lineno for sub in node.body
                   if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Assign):
                continue
            for target in sub.targets:
                if (isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and target.attr in methods):
                    offenders.append(
                        "line %d: %s.%s shadows the method at line %d"
                        % (sub.lineno, node.name, target.attr, methods[target.attr]))
    return offenders


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_no_attribute_shadows_a_method(module_name, path):
    # An instance attribute wins over a method of the same name, so the method
    # becomes uncallable and every caller gets a TypeError.
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = shadowing_offenders(tree)

    assert not offenders, f"{module_name}: {offenders}"


###########################################################
# Predicate return types
###########################################################

PREDICATE_PREFIXES = (
    "is_", "has_", "can_", "should_", "are_", "does_", "was_",
    "allow_", "use_", "force_", "include_",
)


def non_boolean_predicate_returns(tree):
    def shape(node):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "len"):
            return "len()"
        if isinstance(node, ast.BoolOp) and node.values:
            last = node.values[-1]
            if (isinstance(last, ast.Call) and isinstance(last.func, ast.Name)
                    and last.func.id == "len"):
                return "and len()"
        return None

    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith(PREDICATE_PREFIXES):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and sub.value is not None:
                found = shape(sub.value)
                if found:
                    offenders.append("line %d: %s returns %s" % (sub.lineno, node.name, found))
    return offenders


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_every_predicate_returns_a_boolean(module_name, path):
    # A count is truthy in the same places a boolean is, until a caller
    # compares against True or serializes the result.
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = non_boolean_predicate_returns(tree)

    assert not offenders, f"{module_name}: {offenders}"


###########################################################
# Unchecked results
###########################################################

RESULT_NAMES = {"success", "code", "result", "ok"}


def unchecked_result_assignments(tree):
    offenders = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assigns = {}
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in RESULT_NAMES:
                        assigns.setdefault(target.id, node.lineno)
        reads = {node.id for node in ast.walk(func)
                 if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        for name, line in assigns.items():
            if name not in reads:
                offenders.append("line %d: %s() assigns %s and never reads it"
                                 % (line, func.name, name))
    return offenders


@pytest.mark.parametrize("module_name,path", MODULES, ids = MODULE_IDS)
def test_no_result_is_assigned_and_ignored(module_name, path):
    # A batch that captures each step's result and then returns True anyway
    # reports success for a run that failed partway through.
    with open(path, "r", encoding = "utf-8") as handle:
        tree = ast.parse(handle.read())

    offenders = unchecked_result_assignments(tree)

    assert not offenders, f"{module_name}: {offenders}"
