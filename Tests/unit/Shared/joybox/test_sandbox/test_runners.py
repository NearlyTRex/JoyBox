# Local imports
from joybox import sandbox
from sandbox_helpers import WINE, SANDBOXIE, NEITHER


###########################################################
# Runners
#
# Which tool runs a prefix and which of its processes a launch waits on.
###########################################################

def test_blocking_processes_are_copied_not_shared():
    # The caller's list is reused across launches.
    initial = ["game.exe"]
    sandbox.get_blocking_processes(NEITHER(), initial)

    assert initial == ["game.exe"]


def test_a_non_prefix_blocks_only_what_it_was_given():
    assert sandbox.get_blocking_processes(NEITHER(), ["game.exe"]) == ["game.exe"]


def test_each_runner_blocks_on_its_own_processes(monkeypatch):
    monkeypatch.setattr(sandbox.programs, "get_tool_program", lambda name: name)

    assert sandbox.get_blocking_processes(WINE(), ["game.exe"]) == ["game.exe", "WineServer"]
    assert sandbox.get_blocking_processes(SANDBOXIE()) == \
        ["Sandboxie", "SandboxieIni", "SandboxieRpcss", "SandboxieDcomlaunch"]


def test_the_runners_are_the_configured_tools(monkeypatch):
    monkeypatch.setattr(sandbox.programs, "get_tool_program", lambda name: "/tools/" + name)

    assert sandbox.get_wine_command() == "/tools/Wine"
    assert sandbox.get_sandboxie_command() == "/tools/Sandboxie"


def test_sandboxie_needs_no_libraries_installed(monkeypatch):
    reached = []
    monkeypatch.setattr(sandbox, "install_wine_dlls", lambda *args, **kwargs: reached.append("wine"))

    sandbox.install_dlls(SANDBOXIE(), dlls_32 = ["a.dll"])

    assert reached == []
