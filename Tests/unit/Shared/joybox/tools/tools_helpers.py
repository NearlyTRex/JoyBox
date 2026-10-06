# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import network
from joybox import platform_info
from joybox import programs
from joybox import release
from joybox import requirements
from joybox import toolbase

# Every helper a tool's setup, offline setup or configure hands work to
SEAMS = {
    release: [
        "download_github_release",
        "download_general_release",
        "download_webpage_release",
        "build_appimage_from_source",
        "build_binary_from_source",
        "setup_stored_release",
    ],
    network: ["download_github_repository", "archive_github_repository"],
    requirements: ["setup_tool_requirements", "setup_tool_requirements_offline"],
    fileops: ["copy_file_or_directory", "touch_file"],
}

# Choices a download makes that a stored install has to repeat
KEYS = ["search_file", "install_files", "release_type", "chmod_files", "rename_files"]

PARAMS = {"verbose": True, "pretend_run": True, "exit_on_failure": True}
LOCKER = "test-locker"


###########################################################
# Recording double
###########################################################

class Steps:
    # Records every helper call in order and fails the one numbered fail_at.
    def __init__(self, monkeypatch):
        self.calls = []
        self.errors = []
        self.fail_at = None
        self.installed = True
        self.platform = "linux"
        for module, names in SEAMS.items():
            for name in names:
                monkeypatch.setattr(module, name, self.seam(name))
        monkeypatch.setattr(programs, "should_program_be_installed", lambda *args: self.installed)
        monkeypatch.setattr(programs, "should_library_be_installed", lambda *args: self.installed)
        monkeypatch.setattr(programs, "get_program_install_dir", lambda *args: self.dir("/install", *args))
        monkeypatch.setattr(programs, "get_library_install_dir", lambda *args: self.dir("/install", *args))
        monkeypatch.setattr(programs, "get_program_backup_dir", lambda *args: self.dir("/backup", *args))
        monkeypatch.setattr(programs, "get_library_backup_dir", lambda *args: self.dir("/backup", *args))
        monkeypatch.setattr(environment, "get_tools_root_dir", lambda: "/tools")
        monkeypatch.setattr(environment, "get_scripts_icons_dir", lambda: "/icons")
        monkeypatch.setattr(platform_info, "is_linux_platform", lambda: self.platform == "linux")
        monkeypatch.setattr(platform_info, "is_windows_platform", lambda: self.platform == "windows")
        monkeypatch.setattr(logger, "log_error", lambda message, *args, **kwargs: self.errors.append(str(message)))

    @staticmethod
    def dir(root, *parts):
        return "/".join([root] + [part for part in parts if part])

    def seam(self, name):
        def step(*args, **kwargs):
            self.calls.append((name, kwargs))
            return len(self.calls) - 1 != self.fail_at
        return step

    def reset(self, fail_at = None):
        self.calls = []
        self.errors = []
        self.fail_at = fail_at

    def names(self):
        return [name for name, kwargs in self.calls]

    def made(self, name):
        return [kwargs for called, kwargs in self.calls if called == name]


###########################################################
# Contracts every tool keeps
###########################################################

def lifecycle(tool):
    methods = ["setup", "setup_offline"]
    if type(tool).configure is not toolbase.ToolBase.configure:
        methods.append("configure")
    return methods


def assert_a_failed_step_stops_the_install(steps, tool):
    for method in lifecycle(tool):
        steps.reset()
        assert getattr(tool, method)() is True, method
        taken = len(steps.calls)
        assert taken, method
        for index in range(taken):
            steps.reset(fail_at = index)
            assert getattr(tool, method)() is False, (method, index)
            assert len(steps.calls) == index + 1, (method, index)
            assert steps.errors, (method, index)


def assert_nothing_runs_when_already_installed(steps, tool):
    steps.installed = False
    for method in ["setup", "setup_offline"]:
        steps.reset()
        assert getattr(tool, method)() is True
        assert steps.calls == [], method


def assert_setup_params_reach_every_step(steps, tool):
    params = config.SetupParams(locker_type = LOCKER, **PARAMS)
    for method in lifecycle(tool):
        steps.reset()
        assert getattr(tool, method)(setup_params = params) is True
        assert steps.calls, method
        for name, kwargs in steps.calls:
            assert {key: kwargs[key] for key in PARAMS} == PARAMS, (method, name)
            assert kwargs.get("locker_type", LOCKER) == LOCKER, (method, name)


def online_installs(calls):
    installs = []
    repositories = {}
    for name, kwargs in calls:
        if name == "download_github_repository":
            repositories[kwargs["github_repo"]] = kwargs["output_dir"]
        elif name == "archive_github_repository":
            installs.append((repositories[kwargs["github_repo"]], kwargs["output_dir"], {}))
        elif "install_dir" in kwargs:
            installs.append((kwargs["install_dir"], kwargs["backups_dir"], kwargs))
    return installs


def installed_to(steps):
    return [install_dir for install_dir, backup_dir, kwargs in online_installs(steps.calls)]


def assert_offline_matches_online(steps, tool):
    steps.reset()
    assert tool.setup()
    online = online_installs(steps.calls)
    online_requirements = [kwargs["tool_name"] for kwargs in steps.made("setup_tool_requirements")]

    steps.reset()
    assert tool.setup_offline()
    offline = {kwargs["install_dir"]: kwargs for kwargs in steps.made("setup_stored_release")}
    offline_requirements = [kwargs["tool_name"] for kwargs in steps.made("setup_tool_requirements_offline")]

    # Offline restores every install from the archive the download left behind
    assert online
    assert sorted((install_dir, backup_dir) for install_dir, backup_dir, kwargs in online) == \
        sorted((install_dir, kwargs["archive_dir"]) for install_dir, kwargs in offline.items())
    assert online_requirements == offline_requirements

    # Offline installs only the files a fresh download would
    for install_dir, backup_dir, kwargs in online:
        expected = {key: kwargs[key] for key in KEYS if key in kwargs}
        assert {key: offline[install_dir].get(key) for key in expected} == expected
