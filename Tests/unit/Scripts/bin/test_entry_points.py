# Imports
import ast
import os

# Third-party imports
import pytest


###########################################################
# Entry point conventions
#
# Scripts/bin holds thin CLI wrappers by design: parse arguments, dispatch into
# Shared/joybox, print the result. The logic lives in Shared so it can be reused
# and tested directly. These tests protect that shape rather than testing the
# wrappers themselves, which would mostly be testing argparse.
###########################################################

def parse_script(path):
    with open(path, "r") as script_file:
        return ast.parse(script_file.read()), script_file


def top_level_functions(tree):
    return [
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def top_level_classes(tree):
    return [node.name for node in tree.body if isinstance(node, ast.ClassDef)]


def script_ids(script_files):
    return [name for name, _ in script_files]


def test_scripts_were_discovered(script_files):
    # Guards the fixture: an empty list would make every test below vacuous.
    assert len(script_files) > 50, f"only found {len(script_files)} scripts"


def test_every_script_defines_main(script_files):
    offenders = []
    for name, path in script_files:
        with open(path, "r") as script_file:
            tree = ast.parse(script_file.read())
        if "main" not in top_level_functions(tree):
            offenders.append(name)
    assert not offenders, f"scripts with no main(): {offenders}"


def test_every_script_guards_its_entry_point(script_files):
    # Without the guard, importing the module runs it.
    offenders = []
    for name, path in script_files:
        with open(path, "r") as script_file:
            source = script_file.read()
        if '__name__ == "__main__"' not in source and "__name__ == '__main__'" not in source:
            offenders.append(name)
    assert not offenders, f"scripts with no __main__ guard: {offenders}"


def test_run_main_is_only_called_under_the_guard(script_files):
    # The guard has to actually wrap the call, not merely exist somewhere in
    # the file.
    offenders = []
    for name, path in script_files:
        with open(path, "r") as script_file:
            tree = ast.parse(script_file.read())
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                target = getattr(call.func, "attr", getattr(call.func, "id", ""))
                if target == "run_main":
                    offenders.append(name)
    assert not offenders, f"scripts calling run_main at module level: {offenders}"


def test_no_script_defines_a_class(script_files):
    # A class in a CLI wrapper is a strong signal that modelling has leaked out
    # of Shared and into the entry point.
    offenders = []
    for name, path in script_files:
        with open(path, "r") as script_file:
            tree = ast.parse(script_file.read())
        classes = top_level_classes(tree)
        if classes:
            offenders.append(f"{name}: {classes}")
    assert not offenders, f"scripts defining classes: {offenders}"


def test_every_script_imports_from_shared(script_files):
    # A wrapper that never reaches into joybox is either dead or is carrying
    # logic it should be delegating.
    offenders = []
    for name, path in script_files:
        with open(path, "r") as script_file:
            source = script_file.read()
        if "joybox" not in source:
            offenders.append(name)
    assert not offenders, f"scripts not importing from Shared/joybox: {offenders}"


def test_no_script_carries_logic_beyond_main(script_files):
    # Scripts/bin are thin CLI wrappers: parse arguments, dispatch into
    # Shared/joybox, return. A module-level helper is logic that belongs in
    # Shared. Closures inside main() are fine.
    offenders = []
    for name, path in script_files:
        with open(path, "r") as script_file:
            tree = ast.parse(script_file.read())
        extra = [function for function in top_level_functions(tree) if function != "main"]
        if extra:
            offenders.append(f"{name}: {extra}")
    assert not offenders, (
        "scripts defining logic beyond main() - move it into Shared/joybox:\n  "
        + "\n  ".join(offenders))
