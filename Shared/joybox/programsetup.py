# Installing a tool or emulator from the [[setup]] and [[setup_offline]] steps
# in its program.toml, so a program whose setup is only downloads and builds
# needs no setup code of its own.
#
# Each step names a kind, the platform it installs (a program platform, or a
# library's sub folder such as "lib"), `for = "library"` when it installs into
# the program's library dirs, `program` when it installs another program than
# the one the data belongs to (a tool that ships several), and that kind's own
# arguments. A release_type is given by its config.ReleaseType member name. The runner adds
# what every step of a kind needs: the program's name, its install and backups
# dirs for the platform, the locker and the run flags. A string argument that is
# "{program_config:<key>}" is that key of the program's own config.
#
# Steps run in order. Consecutive steps for the same target and platform form a
# group that runs only when that target still needs installing, decided once
# before the group starts, so a library's archive step still runs after its
# download filled the install dir.

# Imports
import re

# Local imports
from joybox import config
from joybox import logger
from joybox import network
from joybox import programcatalog
from joybox import programs
from joybox import release
from joybox import requirements
from joybox import sourcebuild

# A step argument that names a key of the program's own config
PROGRAM_CONFIG_VALUE = re.compile(r"^\{program_config:([A-Za-z0-9_]+)\}$")

# The steps a program installs with, and the module function each kind calls,
# looked up when the step runs
STEP_KINDS = {
    "webpage_release": (release, "download_webpage_release"),
    "github_release": (release, "download_github_release"),
    "general_release": (release, "download_general_release"),
    "appimage_build": (sourcebuild, "build_appimage_from_source"),
    "binary_build": (sourcebuild, "build_binary_from_source"),
    "stored_release": (release, "setup_stored_release"),
    "github_repository": (network, "download_github_repository"),
    "github_archive": (network, "archive_github_repository"),
    "tool_requirements": (requirements, "setup_tool_requirements"),
    "tool_requirements_offline": (requirements, "setup_tool_requirements_offline"),
}

# Kinds that download a release or build one, filed under the backups dir
RELEASE_KINDS = ("webpage_release", "github_release", "general_release", "appimage_build", "binary_build")

# Keys a step uses for itself rather than passing on
STEP_KEYS = ("kind", "platform", "for", "program")

# The program a step installs: the one it names, otherwise the program the data belongs to
def get_step_program(name, step):
    return step.get("program", name)

# Where a step installs: the library dirs when it says so, otherwise the program dirs
def get_step_dirs(name, step):
    platform = step.get("platform")
    if step.get("for") == "library":
        return programs.get_library_install_dir(name, platform), programs.get_library_backup_dir(name, platform)
    return programs.get_program_install_dir(name, platform), programs.get_program_backup_dir(name, platform)

# Whether a step's target still needs installing
def should_install(name, step):
    if step.get("for") == "library":
        return programs.should_library_be_installed(name)
    return programs.should_program_be_installed(name, step.get("platform"))

# The arguments the runner adds to a step of each kind
def get_added_arguments(name, step, setup_params):
    kind = step["kind"]
    install_dir, backups_dir = get_step_dirs(name, step)
    flags = {"verbose": setup_params.verbose, "pretend_run": setup_params.pretend_run, "exit_on_failure": setup_params.exit_on_failure}
    if kind in RELEASE_KINDS:
        return {"install_name": name, "install_dir": install_dir, "backups_dir": backups_dir, "locker_type": setup_params.locker_type, **flags}
    if kind == "stored_release":
        return {"install_name": name, "install_dir": install_dir, "archive_dir": backups_dir, **flags}
    if kind == "github_repository":
        return {"output_dir": install_dir, **flags}
    if kind == "github_archive":
        return {"output_dir": backups_dir, "locker_type": setup_params.locker_type, **flags}
    return {"tool_name": name, **flags}

# A step argument with any {program_config:<key>} filled in from the program's config,
# and a release_type turned into its config.ReleaseType member
def fill_argument(family, name, key, value):
    if key == "release_type":
        return config.ReleaseType[value]
    match = PROGRAM_CONFIG_VALUE.match(value) if isinstance(value, str) else None
    if not match:
        return value
    if family == programcatalog.FAMILY_EMULATORS:
        return programs.get_emulator_config_value(name, match[1])
    return programs.get_tool_config_value(name, match[1])

# Run one step; False when its kind's function reports a failure
def run_step(family, name, step, setup_params):
    if step.get("kind") not in STEP_KINDS:
        raise ValueError("Unknown setup step kind '%s' in %s's program data" % (step.get("kind"), name))
    program = get_step_program(name, step)
    arguments = {key: fill_argument(family, program, key, value) for key, value in step.items() if key not in STEP_KEYS}
    arguments.update({key: value for key, value in get_added_arguments(program, step, setup_params).items() if key not in arguments})
    module, function_name = STEP_KINDS[step["kind"]]
    return getattr(module, function_name)(**arguments)

# Steps split into runs of the same program, target and platform, in order
def group_steps(steps):
    groups = []
    for step in steps:
        key = (step.get("program"), step.get("for"), step.get("platform"))
        if groups and groups[-1][0] == key:
            groups[-1][1].append(step)
        else:
            groups.append((key, [step]))
    return [group for _, group in groups]

# Run a program's setup or offline setup steps; True when it has none, False at the first failure
def run_setup_steps(family, name, offline = False, setup_params = None):
    if not setup_params:
        setup_params = config.SetupParams()
    for group in group_steps(programcatalog.get_setup_steps(family, name, offline)):
        if not should_install(get_step_program(name, group[0]), group[0]):
            continue
        for step in group:
            if not run_step(family, name, step, setup_params):
                logger.log_error("Could not setup %s" % get_step_program(name, step))
                return False
    return True
