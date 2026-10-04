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


###########################################################
# Arguments
###########################################################

@pytest.fixture
def created(isolated_settings, components, monkeypatch):
    # The keyword arguments create_environment was called with
    environment = FakeEnvironment()
    environment.available_components = components
    requests = []
    monkeypatch.setattr(runner, "create_environment", lambda **kwargs: requests.append(kwargs) or environment)
    return requests


@pytest.fixture
def logged(monkeypatch):
    messages = []
    monkeypatch.setattr(cli.logger, "log_info", messages.append)
    return messages


def test_an_action_is_required(run_bootstrap):
    with pytest.raises(SystemExit) as exit_info:
        run_bootstrap()

    assert exit_info.value.code == 2


def test_a_remote_machine_needs_a_server(run_bootstrap, created):
    with pytest.raises(SystemExit):
        cli.main(["-t", "remote_ubuntu", "-a", "setup"])

    assert created == []


def test_a_remote_machine_is_reached_through_its_server(run_bootstrap, created, isolated_settings):
    cli.main(["-t", "remote_ubuntu", "-s", "1", "-k", "/keys/id", "-a", "setup",
              "-c", isolated_settings.get_settings_file()])

    assert created[0]["server_index"] == 1
    assert created[0]["ssh_key_filepath"] == "/keys/id"
    assert created[0]["require_domain"] is True


def test_a_negative_server_index_is_no_server(run_bootstrap, created):
    run_bootstrap("-s", "-1", "-a", "setup")

    assert created[0]["server_index"] is None


def test_run_flags_reach_the_environment(run_bootstrap, created):
    run_bootstrap("-a", "setup", "-v", "-p", "-x", "-f", "--autoremove", "--purge-data",
                  "--backup-id", "latest", "--confirm", "restore")
    flags = created[0]["flags"]

    assert (flags.verbose, flags.pretend_run, flags.exit_on_failure) == (True, True, True)
    assert (flags.force, flags.autoremove, flags.purge_data) == (True, True, True)
    assert (flags.backup_id, flags.confirm) == ("latest", "restore")


def test_no_environment_is_a_failure(isolated_settings, monkeypatch):
    monkeypatch.setattr(runner, "create_environment", lambda **kwargs: None)

    with pytest.raises(SystemExit):
        cli.main(["-t", "local_ubuntu", "-a", "setup", "-c", isolated_settings.get_settings_file()])


###########################################################
# Config file
###########################################################

def test_setup_creates_a_missing_config_file(created, components, tmp_path):
    config_file = tmp_path / "new" / "JoyBox.ini"
    config_file.parent.mkdir()

    cli.main(["-t", "local_ubuntu", "-a", "setup", "-c", str(config_file)])

    assert config_file.is_file()
    assert components["first"].calls == ["install"]


def test_an_uncreatable_config_file_stops_setup(created, components, tmp_path, monkeypatch):
    monkeypatch.setattr(cli.default_settings, "create_default_config_file", lambda path: False)

    with pytest.raises(SystemExit):
        cli.main(["-t", "local_ubuntu", "-a", "setup", "-c", str(tmp_path / "absent.ini")])

    assert created == []


def test_other_actions_need_an_existing_config_file(created, tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["-t", "local_ubuntu", "-a", "status", "-c", str(tmp_path / "absent.ini")])

    assert not (tmp_path / "absent.ini").exists()


###########################################################
# Listings
###########################################################

def test_components_are_listed_without_an_action(created, logged, tmp_path):
    cli.main(["-t", "local_ubuntu", "--list-components", "-c", str(tmp_path / "absent.ini")])

    assert created[0]["require_domain"] is False
    assert logged[-3:] == ["  - first", "  - second", "  - third"]
    assert not (tmp_path / "absent.ini").exists()


def test_images_show_their_pins_and_overrides(isolated_settings, created, logged, monkeypatch):
    monkeypatch.setattr(cli.packages, "docker_images", {
        "gitea": {"GITEA_IMAGE": "gitea/gitea:1.0"},
        "adminer": {"ADMINER_IMAGE": "adminer:4"},
    })
    isolated_settings.set_value("UserData.Images", "gitea_image", " gitea/gitea:2.0 ")

    cli.main(["-t", "local_ubuntu", "--list-images", "-c", isolated_settings.get_settings_file()])

    assert "    ADMINER_IMAGE = adminer:4" in logged
    assert "    GITEA_IMAGE = gitea/gitea:2.0 (override; pin is gitea/gitea:1.0)" in logged
    assert logged.index("  adminer:") < logged.index("  gitea:")
    assert created == []


###########################################################
# Components and actions
###########################################################

def test_an_empty_components_list_is_refused(run_bootstrap, components):
    with pytest.raises(SystemExit):
        run_bootstrap("-a", "setup", "--components")

    for installer in components.values():
        assert installer.calls == []


def test_backup_runs_every_component(run_bootstrap, components):
    run_bootstrap("-a", "backup")

    for installer in components.values():
        assert installer.calls == ["backup"]


def test_teardown_runs_every_installed_component(run_bootstrap, components):
    for installer in components.values():
        installer.installed = True

    run_bootstrap("-a", "teardown")

    for installer in components.values():
        assert installer.calls == ["uninstall"]


@pytest.mark.parametrize("args", [
    ["--backup-id", "latest", "--confirm", "restore"],
    ["--components", "first", "--confirm", "restore"],
    ["--components", "first", "--backup-id", "latest"],
    ["--components", "first", "--backup-id", "latest", "--confirm", "yes"],
])
def test_restore_refuses_without_every_safeguard(run_bootstrap, components, args):
    with pytest.raises(SystemExit):
        run_bootstrap("-a", "restore", *args)

    for installer in components.values():
        assert installer.calls == []


@pytest.mark.parametrize("args", [["--confirm", "restore"], ["-p"]])
def test_restore_runs_the_chosen_components(run_bootstrap, components, args):
    run_bootstrap("-a", "restore", "--components", "first", "--backup-id", "latest", *args)

    assert components["first"].calls == ["restore"]
    assert components["second"].calls == []


###########################################################
# Status
###########################################################

def status_of(components, *installers):
    components.clear()
    components.update({installer.name: installer for installer in installers})


def test_status_lists_installed_then_missing(run_bootstrap, components, logged):
    status_of(components,
        RecordingInstaller("nginx", package_status = None),
        RecordingInstaller("aptget", installed = True,
            package_status = {"installed": ["curl", "git"], "missing": ["jq"]}),
        RecordingInstaller("docker", installed = True, package_status = None),
        RecordingInstaller("flatpak", package_status = {"installed": ["a"], "missing": []}),
        RecordingInstaller("dotfiles"))

    run_bootstrap("-a", "status")

    body = logged[logged.index("Installed (2):"):]
    assert body == [
        "Installed (2):",
        "  [x] aptget (2/3 packages)",
        "  [x] docker",
        "Not installed (3):",
        "  [ ] dotfiles (0/1 packages)",
        "      Missing:",
        "        - dotfiles",
        "  [ ] flatpak",
        "  [ ] nginx",
    ]


def test_status_counts_an_installed_components_packages(run_bootstrap, components, logged):
    status_of(components, RecordingInstaller("aptget", installed = True))

    run_bootstrap("-a", "status")

    assert logged[-2:] == ["Installed (1):", "  [x] aptget (1/1 packages)"]


def test_status_names_the_first_ten_missing_packages(run_bootstrap, components, logged):
    missing = ["pkg%02d" % index for index in range(12)]
    status_of(components,
        RecordingInstaller("aptget", package_status = {"installed": ["curl"], "missing": missing}))

    run_bootstrap("-a", "status")

    body = logged[logged.index("Not installed (1):"):]
    assert body[1:3] == ["  [ ] aptget (1/13 packages)", "      Missing:"]
    assert body[3:13] == ["        - %s" % name for name in missing[:10]]
    assert body[13:] == ["        ... and 2 more"]
    assert not any(line.startswith("Installed") for line in logged)


def test_status_with_nothing_reports_no_groups(run_bootstrap, components, logged):
    status_of(components)

    run_bootstrap("-a", "status")

    assert not any(line.startswith(("Installed", "Not installed")) for line in logged)
