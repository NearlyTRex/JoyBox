# Imports
import ast

###########################################################
# Entry point conventions
#
# joybox.cli holds thin command wrappers by design: build a parser, dispatch
# into joybox, print the result. The logic lives elsewhere in joybox so it can
# be reused and tested directly. These tests protect that shape rather than
# testing the wrappers themselves, which would mostly be testing argparse.
###########################################################

# The only functions a command module defines
COMMAND_FUNCTIONS = ["build_parser", "main", "run"]


def parse_module(path):
    with open(path, "r") as module_file:
        return ast.parse(module_file.read())


def top_level_functions(tree):
    return [
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def test_commands_were_discovered(cli_files, cli_commands):
    # Guards the fixtures: an empty list would make every test below vacuous.
    assert len(cli_files) > 50, f"only found {len(cli_files)} command modules"
    assert len(cli_commands) == len(cli_files)


def test_every_module_is_a_command(cli_files, cli_commands):
    # A module without a [project.scripts] entry is never installed as a
    # command, and an entry without a module fails when it is run.
    modules = {name for name, _ in cli_files}
    targets = {module.rsplit(".", 1)[-1] for _, module in cli_commands}

    assert sorted(modules - targets) == [], "modules with no [project.scripts] entry"
    assert sorted(targets - modules) == [], "[project.scripts] entries with no module"


def test_every_command_runs_through_run(pyproject_path):
    import tomllib
    with open(pyproject_path, "rb") as pyproject_file:
        scripts = tomllib.load(pyproject_file)["project"]["scripts"]

    wrong = [command for command, target in scripts.items() if not target.endswith(":run")]
    assert not wrong, f"commands that bypass run() and its error handling: {wrong}"


def test_every_module_defines_exactly_the_command_functions(cli_files):
    # A module-level helper is logic that belongs elsewhere in joybox.
    # Closures inside main() are fine.
    offenders = []
    for name, path in cli_files:
        functions = top_level_functions(parse_module(path))
        if sorted(functions) != sorted(COMMAND_FUNCTIONS):
            offenders.append(f"{name}: {functions}")
    assert not offenders, "modules not defining exactly %s:\n  %s" % (
        COMMAND_FUNCTIONS, "\n  ".join(offenders))


def test_importing_a_module_runs_nothing(cli_files):
    # Everything happens inside the functions, so a module can be imported to
    # build its parser (the command reference does) without parsing sys.argv.
    allowed = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef)
    offenders = []
    for name, path in cli_files:
        for node in parse_module(path).body:
            if isinstance(node, allowed):
                continue
            if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test):
                continue
            offenders.append(f"{name}: {ast.unparse(node)[:60]}")
    assert not offenders, "module-level statements:\n  " + "\n  ".join(offenders)


def test_the_main_guard_calls_run(cli_files):
    offenders = []
    for name, path in cli_files:
        guards = [
            node for node in parse_module(path).body
            if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)]
        if len(guards) != 1 or ast.unparse(guards[0].body[0]) != "run()":
            offenders.append(name)
    assert not offenders, f"modules whose __main__ guard does not call run(): {offenders}"


def test_no_module_defines_a_class(cli_files):
    # A class in a command wrapper is a strong signal that modelling has leaked
    # out of joybox and into the entry point.
    offenders = []
    for name, path in cli_files:
        classes = [node.name for node in parse_module(path).body if isinstance(node, ast.ClassDef)]
        if classes:
            offenders.append(f"{name}: {classes}")
    assert not offenders, f"modules defining classes: {offenders}"


def test_every_module_imports_from_joybox(cli_files):
    # A wrapper that never reaches into joybox is either dead or is carrying
    # logic it should be delegating.
    offenders = []
    for name, path in cli_files:
        imported = [
            node for node in parse_module(path).body
            if isinstance(node, (ast.Import, ast.ImportFrom)) and "joybox" in ast.unparse(node)]
        if not imported:
            offenders.append(name)
    assert not offenders, f"modules not importing from joybox: {offenders}"
