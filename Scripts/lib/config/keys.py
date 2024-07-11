# Imports
import os
import sys

# Platform keys
platform_key_supercategory = "supercategory"
platform_key_category = "category"
platform_key_subcategory = "subcategory"
platform_key_addons = "addons"
platform_key_launcher = "launcher"
platform_key_autofill_json = "autofill_json"
platform_key_fillonce_json = "fillonce_json"

# Dat keys
dat_key_game = "game"
dat_key_file = "file"
dat_key_size = "size"
dat_key_crc = "crc"
dat_key_md5 = "md5"
dat_key_sha1 = "sha1"
dat_key_sha256 = "sha256"

# Metadata keys
metadata_key_game = "game"
metadata_key_platform = "platform"
metadata_key_supercategory = "supercategory"
metadata_key_category = "category"
metadata_key_subcategory = "subcategory"
metadata_key_file = "file"
metadata_key_description = "description"
metadata_key_genre = "genre"
metadata_key_coop = "coop"
metadata_key_playable = "playable"
metadata_key_developer = "developer"
metadata_key_publisher = "publisher"
metadata_key_players = "players"
metadata_key_release = "release"
metadata_key_background = "background"
metadata_key_boxback = "boxback"
metadata_key_boxfront = "boxfront"
metadata_key_label = "label"
metadata_key_screenshot = "screenshot"
metadata_key_video = "video"
metadata_key_json = "json"
metadata_keys_minimum = [
    metadata_key_game,
    metadata_key_platform,
    metadata_key_file
]
metadata_keys_all = [
    metadata_key_game,
    metadata_key_platform,
    metadata_key_supercategory,
    metadata_key_category,
    metadata_key_subcategory,
    metadata_key_file,
    metadata_key_description,
    metadata_key_genre,
    metadata_key_coop,
    metadata_key_playable,
    metadata_key_developer,
    metadata_key_publisher,
    metadata_key_players,
    metadata_key_release,
    metadata_key_background,
    metadata_key_boxback,
    metadata_key_boxfront,
    metadata_key_label,
    metadata_key_screenshot,
    metadata_key_video,
    metadata_key_json
]

# General json keys
json_key_launch_name = "launch_name"
json_key_launch_file = "launch_file"
json_key_launch_dir = "launch_dir"
json_key_transform_file = "transform_file"
json_key_source_file = "source_file"
json_key_source_dir = "source_dir"
json_key_metadata = "metadata"
json_key_save_dir = "save_dir"
json_key_general_save_dir = "general_save_dir"
json_key_local_cache_dir = "local_cache_dir"
json_key_remote_cache_dir = "remote_cache_dir"
json_key_files = "files"
json_key_dlc = "dlc"
json_key_update = "update"
json_key_extra = "extra"
json_key_dependencies = "dependencies"

# Computer json keys
json_key_installer_exe = "installer_exe"
json_key_installer_dos_exe = "installer_dos_exe"
json_key_installer_type = "installer_type"
json_key_disc_type = "disc_type"
json_key_main_game_exe = "main_game_exe"
json_key_main_game_exe_cwd = "main_game_exe_cwd"
json_key_main_game_exe_args = "main_game_exe_args"
json_key_main_game_dos_exe = "main_game_dos_exe"
json_key_main_game_dos_exe_cwd = "main_game_dos_exe_cwd"
json_key_main_game_dos_exe_args = "main_game_dos_exe_args"
json_key_main_game_win31_exe = "main_game_win31_exe"
json_key_main_game_win31_exe_cwd = "main_game_win31_exe_cwd"
json_key_main_game_win31_exe_args = "main_game_win31_exe_args"
json_key_sandbox = "sandbox"
json_key_sandbox_sandboxie = "sandboxie"
json_key_sandbox_wine = "wine"
json_key_sandbox_wine_tricks = "tricks"
json_key_sandbox_wine_overrides = "overrides"
json_key_sandbox_wine_desktop = "desktop"
json_key_sandbox_wine_use_dxvk = "use_dxvk"
json_key_sandbox_wine_use_vkd3d = "use_vkd3d"
json_key_sandbox_wine_use_virtual_desktop = "use_virtual_desktop"
json_key_steps = "steps"
json_key_steps_preinstall = "preinstall"
json_key_steps_postinstall = "postinstall"
json_key_sync = "sync"
json_key_sync_search = "search"
json_key_sync_data = "data"
json_key_registry = "registry"
json_key_registry_setup_keys = "setup_keys"
json_key_registry_game_keys = "game_keys"
json_key_steam = "steam"
json_key_steam_appid = "appid"
json_key_steam_branchid = "branchid"
json_key_steam_buildid = "buildid"
json_key_steam_builddate = "builddate"
json_key_steam_name = "name"
json_key_steam_controller_support = "controller_support"
json_key_steam_installdir = "installdir"
json_key_steam_paths = "paths"
json_key_steam_keys = "keys"
json_key_gog = "gog"
json_key_gog_appid = "appid"
json_key_gog_appname = "appname"
json_key_gog_name = "name"
json_key_gog_buildid = "buildid"
json_key_gog_paths = "paths"
json_key_gog_keys = "keys"
json_key_epic = "epic"
json_key_epic_appid = "appid"
json_key_epic_paths = "paths"
json_key_epic_keys = "keys"
json_key_winver = "winver"
json_key_is_32_bit = "is_32_bit"
json_key_is_dos = "is_dos"
json_key_is_win31 = "is_win31"
json_key_is_scumm = "is_scumm"

# Json string keys
json_keys_str_keys = [

    # General
    json_key_launch_name,
    json_key_launch_dir,
    json_key_source_dir,

    # Computer
    json_key_installer_type,
    json_key_disc_type,
    json_key_steam_appid,
    json_key_steam_branchid,
    json_key_steam_buildid,
    json_key_steam_builddate,
    json_key_steam_name,
    json_key_steam_controller_support,
    json_key_gog_appid,
    json_key_gog_appname,
    json_key_gog_name,
    json_key_gog_buildid,
    json_key_winver
]

# Json list keys
json_keys_list_keys = [

    # General
    json_key_launch_file,
    json_key_transform_file,
    json_key_source_file,
    json_key_files,
    json_key_dlc,
    json_key_update,
    json_key_extra,
    json_key_dependencies,

    # Computer
    json_key_installer_exe,
    json_key_installer_dos_exe,
    json_key_main_game_exe,
    json_key_main_game_dos_exe,
    json_key_main_game_win31_exe
]

# Json dictionary keys
json_keys_dict_keys = [

    # Computer
    json_key_main_game_exe_cwd,
    json_key_main_game_exe_args,
    json_key_main_game_dos_exe_cwd,
    json_key_main_game_dos_exe_args,
    json_key_main_game_win31_exe_cwd,
    json_key_main_game_win31_exe_args,
    json_key_sandbox,
    json_key_steps,
    json_key_sync,
    json_key_registry,
    json_key_steam,
    json_key_gog
]

# Json bool keys
json_keys_bool_keys = [

    # Computer
    json_key_is_32_bit,
    json_key_is_dos,
    json_key_is_win31,
    json_key_is_scumm
]

# Filter keys
filter_key_launchable_only = "launchable_only"
keys_filter_keys = [
    filter_key_launchable_only
]
