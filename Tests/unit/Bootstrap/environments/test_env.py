# Imports
import pytest

# Local imports
from environments import env
from fakes import RecordingInstaller


###########################################################
# Component processing
#
# Environment.process_components is the orchestration every setup, teardown,
# backup and restore runs through. The ordering and skip rules are the part
# that decides whether a deploy leaves a half-configured box behind.
###########################################################

def build_environment(components):
    environment = env.Environment()
    environment.available_components = components
    return environment


@pytest.fixture
def three_components():
    return {
        "first": RecordingInstaller("first"),
        "second": RecordingInstaller("second"),
        "third": RecordingInstaller("third"),
    }


###########################################################
# Ordering
###########################################################

def build_ordered_components(installed = False):
    call_log = []
    components = {
        name: RecordingInstaller(name, installed = installed, call_log = call_log)
        for name in ["first", "second", "third"]
    }
    return components, call_log


def test_components_install_in_declaration_order():

    # Order is load-bearing: nginx and certbot have to finish before any app
    # formats a vhost pointing at the certificate they produced.
    components, call_log = build_ordered_components()
    environment = build_environment(components)

    assert environment.process_components("install") is True
    assert [name for name, action in call_log] == ["first", "second", "third"]


def test_components_uninstall_in_reverse_order():

    # Teardown has to unwind the dependency order, or nginx goes before the
    # apps whose vhosts it is still serving.
    components, call_log = build_ordered_components(installed = True)
    environment = build_environment(components)

    assert environment.process_components("uninstall", reverse_order = True) is True
    assert [name for name, action in call_log] == ["third", "second", "first"]


###########################################################
# Skip rules
###########################################################

def test_an_installed_component_is_skipped_on_install(three_components):
    three_components["second"].installed = True
    environment = build_environment(three_components)

    environment.process_components("install")

    assert three_components["second"].calls == []
    assert three_components["first"].calls == ["install"]


def test_a_missing_component_is_skipped_on_uninstall(three_components):
    three_components["first"].installed = True
    environment = build_environment(three_components)

    environment.process_components("uninstall")

    assert three_components["first"].calls == ["uninstall"]
    assert three_components["second"].calls == []


def test_force_ignores_the_installed_state(three_components):
    for installer in three_components.values():
        installer.installed = True
    environment = build_environment(three_components)

    environment.process_components("install", force = True)

    for installer in three_components.values():
        assert installer.calls == ["install"]


###########################################################
# Component selection
###########################################################

def test_no_selection_processes_everything(three_components):
    environment = build_environment(three_components)
    environment.set_components_to_process(None)

    environment.process_components("install")

    for installer in three_components.values():
        assert installer.calls == ["install"]


def test_a_selection_limits_what_runs(three_components):
    environment = build_environment(three_components)
    environment.set_components_to_process(["second"])

    environment.process_components("install")

    assert three_components["second"].calls == ["install"]
    assert three_components["first"].calls == []
    assert three_components["third"].calls == []


def test_an_unknown_component_name_aborts(three_components):

    # Quitting beats silently doing nothing: a typo in --components would
    # otherwise look like a successful run that installed none of what was asked.
    environment = build_environment(three_components)

    with pytest.raises(SystemExit):
        environment.set_components_to_process(["nonexistent"])


def test_an_empty_selection_processes_nothing(three_components):
    environment = build_environment(three_components)
    environment.set_components_to_process([])

    environment.process_components("install")

    for installer in three_components.values():
        assert installer.calls == []


###########################################################
# Failure handling
###########################################################

def test_a_failure_stops_the_run_by_default(three_components):

    # Continuing past a failed nginx would install apps whose vhosts cannot
    # load, so the default is to stop where the problem is.
    three_components["first"].results = {"install": False}
    environment = build_environment(three_components)

    assert environment.process_components("install") is False
    assert three_components["second"].calls == []


def test_continue_on_failure_runs_the_rest(three_components):
    three_components["first"].results = {"install": False}
    environment = build_environment(three_components)

    result = environment.process_components("install", continue_on_failure = True)

    assert result is False, "the run still has to report failure"
    assert three_components["second"].calls == ["install"]
    assert three_components["third"].calls == ["install"]


def test_a_clean_run_reports_success(three_components):
    environment = build_environment(three_components)
    assert environment.process_components("install") is True


###########################################################
# Backup and restore
###########################################################

def test_backup_attempts_every_component(three_components):

    # docs/backup.md states this explicitly: one broken service must not
    # silently skip the rest of the sweep.
    three_components["first"].results = {"backup": False}
    environment = build_environment(three_components)

    assert environment.backup() is False
    for installer in three_components.values():
        assert installer.calls == ["backup"]


def test_restore_stops_at_the_first_failure(three_components):

    # Restore overwrites live data, so pressing on after a failure risks
    # leaving a half-restored system.
    three_components["first"].results = {"restore": False}
    environment = build_environment(three_components)

    assert environment.restore() is False
    assert three_components["second"].calls == []


###########################################################
# Status
###########################################################

def test_status_reports_every_component(three_components):
    three_components["second"].installed = True
    environment = build_environment(three_components)

    results = environment.status()

    assert [entry["name"] for entry in results] == ["first", "second", "third"]
    assert [entry["installed"] for entry in results] == [False, True, False]


def test_status_respects_the_selection(three_components):
    environment = build_environment(three_components)
    environment.set_components_to_process(["third"])

    results = environment.status()

    assert [entry["name"] for entry in results] == ["third"]


###########################################################
# Available components
###########################################################

def test_available_components_are_listed(three_components):
    environment = build_environment(three_components)
    assert environment.get_available_components() == ["first", "second", "third"]


def test_the_base_environment_does_not_claim_success():

    # Environment is abstract - a subclass that forgets to override setup must
    # not report a successful provision.
    environment = env.Environment()

    assert environment.setup() is False
    assert environment.teardown() is False
