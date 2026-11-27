# Where each tool's and emulator's programs live, how they run, the config files
# their setup writes and the system files they need: read from the program.toml
# and template files under programdata/, so programs.py can look them up without
# importing any tool or emulator.

# Imports
import configparser
import functools
import os
import re

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import platform_info
from joybox import serialization
from joybox import settings
from joybox.nintendo import switchprofile

###########################################################
# Data files
#
# programdata/<family>/<name>/program.toml holds one program's data:
#   config            the map its class's get_config returns, by program name
#   config_files      files its setup writes, each a path and an optional
#                     template file beside program.toml; no template is an
#                     empty file
#   system_files      system files its setup checks, each a path and its md5
#   only_on           "wine" or "sandboxie": the program exists only there
#   program_unknown_when_unset
#                     a program whose path names an unset setting is unknown
#   platforms         the config.Platform members an emulator plays, by member name
#   setup, setup_offline
#                     the steps that install it, run by joybox/programsetup.py
#   launch            how the program is started. An emulator's args after its
#                     program, and fullscreen_args for a fullscreen launch, where
#                     {game_file}, {game_dir}, {game_name} and {platform_config:<key>}
#                     are filled in by joybox/emulatorbase.py. A tool's args, cwd and
#                     env, where {program_dir} and {command_path:<name>} are filled
#                     in by joybox/toolbase.py
#
# TOML has no null, so "<none>" stands for a value that is not set. A string
# that is one {placeholder} is the value it names, as the settings ini has it; a
# longer one is filled in part by part and the parts joined as a path:
#   {setting:Section.key}         a value from the settings ini
#   {path_setting:Section.key}    a path from the settings ini
#   {optional_path_setting:Section.key}
#                                 the same, empty when it is not set
#   {a|b}                         a, or b when a is empty
#   {firefox_default_profile}     the profile Firefox opens by default
#   {switch_profile_user_id}      the Switch profile from the settings ini,
#   {switch_profile_account_name} or Yuzu's own when it is not a valid one
###########################################################

# The value TOML files use for one that is not set
NONE_VALUE = "<none>"

# Families of programs, each a folder under programdata/
FAMILY_TOOLS = "tools"
FAMILY_EMULATORS = "emulators"

# A {placeholder} in a data string
PLACEHOLDER = re.compile(r"\{([^{}]+)\}")

# Profile Yuzu uses when the settings ini has no valid one
DEFAULT_SWITCH_PROFILE = ("F6F389D41D6BC0BDD6BD928C526AE556", "yuzu")

# Get the folder holding the data of a family of programs
def get_family_dir(family):
    return paths.join_paths(os.path.dirname(os.path.abspath(__file__)), "programdata", family)

# Read every program's data in a family, once, by program name in name order
@functools.cache
def load_family(family):
    family_dir = get_family_dir(family)
    loaded = {}
    for name in sorted(os.listdir(family_dir)):
        program_dir = paths.join_paths(family_dir, name)
        data = serialization.read_toml_file(paths.join_paths(program_dir, "program.toml"), exit_on_failure = True)
        loaded[name] = {"dir": program_dir, "data": data}
    return loaded

###########################################################
# Named lookups
###########################################################

# Where each kind of Firefox install keeps its profiles
def get_profile_roots():
    if platform_info.is_windows_platform():
        return [os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox")]
    home = os.path.expanduser("~")
    return [
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    ]

# Profile path a parsed profiles.ini opens by default: the first [Install...] Default, else the first Default=1 profile; "" when neither
def get_ini_default_profile(parser):
    for section in parser.sections():
        if section.startswith("Install") and parser[section].get("Default"):
            return parser[section]["Default"]
    for section in parser.sections():
        if section.startswith("Profile") and parser[section].get("Default") == "1":
            return parser[section].get("Path", "")
    return ""

# Find the profile Firefox opens by default, or "" when there is none, from the
# [Install...] section; older Firefox's Default=1 can mark one nothing opens
def find_default_profile_dir(profile_roots = None):
    for root in profile_roots if profile_roots is not None else get_profile_roots():
        text = serialization.read_text_file(os.path.join(root, "profiles.ini"))
        if not text:
            continue
        parser = configparser.ConfigParser(interpolation = None)
        try:
            parser.read_string(text)
        except configparser.Error:
            continue
        profile = get_ini_default_profile(parser)
        if not profile:
            continue
        profile_dir = profile if os.path.isabs(profile) else os.path.join(root, profile)
        if paths.does_path_exist(profile_dir):
            return profile_dir
    return ""

# Get the Switch profile from the settings ini, or Yuzu's own when it is not a valid one
def get_switch_profile():
    user_id = settings.get_value("UserData.Switch", "profile_user_id")
    account_name = settings.get_value("UserData.Switch", "profile_account_name")
    if not switchprofile.is_valid_switch_profile_info(user_id, account_name):
        logger.log_warning("No Switch profile found in ini, using default")
        return DEFAULT_SWITCH_PROFILE
    return (user_id, account_name)

###########################################################
# Filling in values
###########################################################

# Look up one single placeholder's value: a setting, a path setting, the Firefox profile or a Switch profile part
def look_up_placeholder(name, asked):
    kind, _, setting = name.partition(":")
    section, _, key = setting.rpartition(".")
    if kind == "setting":
        return settings.get_value(section, key)
    if kind == "path_setting":
        return settings.get_path_value(section, key)
    if kind == "optional_path_setting":
        return settings.get_path_value(section, key, default_value = "", throw_exception = False)
    if name == "firefox_default_profile":
        return find_default_profile_dir()
    if name in ("switch_profile_user_id", "switch_profile_account_name"):
        if "switch_profile" not in asked:
            asked["switch_profile"] = get_switch_profile()
        return asked["switch_profile"][0 if name == "switch_profile_user_id" else 1]
    raise ValueError("Unknown placeholder {%s} in program data" % name)

# Fill in one placeholder; lookups made more than once in a value are asked for once
def fill_placeholder(name, asked):
    if "|" in name:
        for choice in name.split("|"):
            value = fill_placeholder(choice, asked)
            if value:
                return value
        return ""
    if name not in asked:
        asked[name] = look_up_placeholder(name, asked)
    return asked[name]

# Fill in a value from program data: "<none>" is None, and a string with placeholders
# has each part filled in and the parts joined as a path
def fill_value(value, asked, unknown_when_unset = False):
    if isinstance(value, dict):
        return {key: fill_value(item, asked, unknown_when_unset and key == "program") for key, item in value.items()}
    if isinstance(value, list):
        return [fill_value(item, asked) for item in value]
    if value == NONE_VALUE:
        return None
    if not isinstance(value, str) or not PLACEHOLDER.search(value):
        return value
    whole = PLACEHOLDER.fullmatch(value)
    if whole:
        return fill_placeholder(whole.group(1), asked)
    parts = []
    for part in value.split("/"):
        filled = PLACEHOLDER.sub(lambda match: str(fill_placeholder(match.group(1), asked) or ""), part)
        if unknown_when_unset and PLACEHOLDER.search(part) and not filled:
            return None
        parts.append(filled)
    return paths.join_paths(*parts)

# Whether a program exists on this platform
def is_present(data):
    only_on = data.get("only_on")
    if only_on is None:
        return True
    if only_on == "wine":
        return platform_info.is_wine_platform()
    if only_on == "sandboxie":
        return platform_info.is_sandboxie_platform()
    raise ValueError("Unknown only_on '%s' in program data" % only_on)

###########################################################
# Lookups
###########################################################

# Get a program's config by its name: the map its class's get_config returns, filled in fresh
def get_config(family, name):
    entry = load_family(family).get(name)
    if not entry or not is_present(entry["data"]):
        return {}
    data = entry["data"]
    return {
        program: fill_value(value, {}, data.get("program_unknown_when_unset", False))
        for program, value in data.get("config", {}).items()}

# Get every program's config in a family, merged into one map of program name to config
def get_configs(family):
    merged = {}
    for name in load_family(family):
        merged.update(get_config(family, name))
    return merged

# Get the files a program's setup writes, by path, with their contents
def get_config_files(family, name):
    entry = load_family(family).get(name)
    if not entry:
        return {}
    files = {}
    for config_file in entry["data"].get("config_files", []):
        template = config_file.get("template")
        contents = ""
        if template:
            contents = serialization.read_text_file(paths.join_paths(entry["dir"], template), exit_on_failure = True)
        files[config_file["path"]] = contents
    return files

# Get the system files a program's setup checks, by path, with their md5
def get_system_files(family, name):
    entry = load_family(family).get(name)
    if not entry:
        return {}
    return {system_file["path"]: system_file["md5"] for system_file in entry["data"].get("system_files", [])}

# Get the platforms a program plays, by its name; none when its data lists none
def get_platforms(family, name):
    entry = load_family(family).get(name)
    if not entry:
        return []
    return [config.Platform[platform] for platform in entry["data"].get("platforms", [])]

# Get a program's setup steps by its name, the offline ones when asked; none when its data lists none
def get_setup_steps(family, name, offline = False):
    entry = load_family(family).get(name)
    if not entry:
        return []
    return [dict(step) for step in entry["data"].get("setup_offline" if offline else "setup", [])]

# Get a program's launch table by its name: args, and fullscreen_args added for a fullscreen
# launch; empty when its data has none
def get_launch(family, name):
    entry = load_family(family).get(name)
    if not entry:
        return {}
    return dict(entry["data"].get("launch", {}))

# Get a tool's config by its name
def get_tool_config(name):
    return get_config(FAMILY_TOOLS, name)

# Get every tool's config, merged into one map of program name to config
def get_tool_configs():
    return get_configs(FAMILY_TOOLS)

# Get an emulator's config by its name
def get_emulator_config(name):
    return get_config(FAMILY_EMULATORS, name)

# Get every emulator's config, merged into one map of program name to config
def get_emulator_configs():
    return get_configs(FAMILY_EMULATORS)

# Get the platforms an emulator plays, by its name
def get_emulator_platforms(name):
    return get_platforms(FAMILY_EMULATORS, name)
