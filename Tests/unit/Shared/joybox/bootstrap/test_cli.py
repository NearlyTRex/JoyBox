# Imports
import pytest

# Local imports
from joybox.bootstrap import cli
from joybox.bootstrap import picker
from joybox.bootstrap import runner
from joybox.bootstrap.environments import env
from fakes import RecordingInstaller


###########################################################
# bootstrap.py end to end, with a fake environment
###########################################################

class FakeEnvironment(env.Environment):
    def setup(self):
        return self.process_components("install", continue_on_failure = True)

    def teardown(self):
        return self.process_components("uninstall", reverse_order = True, continue_on_failure = True)


@pytest.fixture
def components():
    return {name: RecordingInstaller(name) for name in ["first", "second", "third"]}


@pytest.fixture
def run_bootstrap(isolated_settings, components, monkeypatch):
    environment = FakeEnvironment()
    environment.available_components = components
    monkeypatch.setattr(runner, "create_environment", lambda **kwargs: environment)

    def run(*args):
        return cli.main(["-t", "local_ubuntu", "-c", isolated_settings.get_settings_file()] + list(args))
    return run


@pytest.fixture
def terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)


def test_a_clean_setup_exits_normally(run_bootstrap, components):
    run_bootstrap("-a", "setup")
    for installer in components.values():
        assert installer.calls == ["install"]


def test_a_failed_component_fails_the_run(run_bootstrap, components):
    # install.sh and CI only see the exit code.
    components["second"].results = {"install": False}

    with pytest.raises(SystemExit) as exit_info:
        run_bootstrap("-a", "setup")

    assert exit_info.value.code == 1


###########################################################
# --interactive
###########################################################

def test_interactive_runs_only_the_picked_components(run_bootstrap, components, terminal, monkeypatch):
    monkeypatch.setattr(picker, "choose_components", lambda names, action: ["first", "third"])

    run_bootstrap("-a", "setup", "--interactive")

    assert components["first"].calls == ["install"]
    assert components["second"].calls == []
    assert components["third"].calls == ["install"]


def test_interactive_offers_every_available_component(run_bootstrap, terminal, monkeypatch):
    offered = []
    monkeypatch.setattr(picker, "choose_components",
        lambda names, action: offered.append((names, action)) or names)

    run_bootstrap("-a", "teardown", "-i")

    assert offered == [(["first", "second", "third"], "teardown")]


def test_quitting_the_menu_changes_nothing(run_bootstrap, components, terminal, monkeypatch):
    monkeypatch.setattr(picker, "choose_components", lambda names, action: None)

    run_bootstrap("-a", "setup", "--interactive")

    for installer in components.values():
        assert installer.calls == []


@pytest.mark.parametrize("args", [
    ["-a", "status", "--interactive"],
    ["-a", "backup", "--interactive"],
    ["-a", "setup", "--interactive", "--components", "first"],
])
def test_interactive_refuses_what_it_cannot_honour(run_bootstrap, components, terminal, args):
    with pytest.raises(SystemExit):
        run_bootstrap(*args)
    for installer in components.values():
        assert installer.calls == []


def test_interactive_without_a_terminal_refuses_rather_than_hanging(run_bootstrap, components, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    with pytest.raises(SystemExit):
        run_bootstrap("-a", "setup", "--interactive")
    for installer in components.values():
        assert installer.calls == []
