# Imports
import ast
import glob
import inspect
import os

# Local imports
from joybox import network, release
from joybox import tools
from joybox import toolbase


###########################################################
# Calls into the download helpers
#
# Tool setup only runs when a tool is installed, so a keyword a helper does
# not take (a branch passed to a release download, say) would only surface as
# a crash on someone's machine.
###########################################################

HELPERS = {
    "network.download_github_repository": network.download_github_repository,
    "network.archive_github_repository": network.archive_github_repository,
    "release.download_github_release": release.download_github_release,
}


def test_every_keyword_is_one_the_helper_takes(shared_dir):
    wrong = []
    for path in sorted(glob.glob(os.path.join(shared_dir, "joybox", "tools", "*.py"))):
        for node in ast.walk(ast.parse(open(path).read())):
            if not isinstance(node, ast.Call):
                continue
            helper = HELPERS.get(ast.unparse(node.func))
            if helper is None:
                continue
            accepted = inspect.signature(helper).parameters
            for keyword in node.keywords:
                if keyword.arg not in accepted:
                    wrong.append("%s:%d %s(%s=)" % (
                        os.path.basename(path), node.lineno, ast.unparse(node.func), keyword.arg))
    assert not wrong, "keywords the helper does not take:\n  " + "\n  ".join(wrong)


###########################################################
# Tool registry
###########################################################

def test_the_map_is_keyed_by_each_tool_name():
    tool_map = tools.get_tool_map()
    exported = [value for value in vars(tools).values()
                if isinstance(value, type) and issubclass(value, toolbase.ToolBase)]

    # Every tool the package exports is registered
    assert sorted(type(tool).__name__ for tool in tool_map.values()) == sorted(cls.__name__ for cls in exported)
    assert all(name == tool.get_name() for name, tool in tool_map.items())


def test_a_tool_is_found_by_name():
    assert isinstance(tools.get_tool_by_name("HacTool"), tools.HacTool)
    assert tools.get_tool_by_name("NoSuchTool") is None


def test_relative_programs_live_under_their_tool_or_entry():
    misplaced = []
    for tool in tools.get_tool_list():
        for entry, values in tool.get_config().items():
            program = values.get("program")
            candidates = program.values() if isinstance(program, dict) else [program]
            for path in candidates:
                if path and not path.startswith("/") and not path.startswith((entry + "/", tool.get_name() + "/")):
                    misplaced.append((entry, path))
    assert misplaced == []
