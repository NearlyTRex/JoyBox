# Imports
import os
import sys

# Platform keys
platform_key_supercategory = "supercategory"
platform_key_category = "category"
platform_key_subcategory = "subcategory"
platform_key_transforms = "transforms"
platform_key_addons = "addons"
platform_key_launcher = "launcher"
platform_key_autofill_json = "autofill_json"
platform_key_fillonce_json = "fillonce_json"

# Metadata keys
metadata_key_game = "game"
metadata_key_platform = "platform"
metadata_key_file = "file"
metadata_key_description = "description"
metadata_key_genre = "genre"
metadata_key_tag = "tag"
metadata_key_coop = "coop"
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

# General json keys
general_key_files = "files"
general_key_launch_name = "launch_name"
general_key_launch_file = "launch_file"
general_key_launch_dir = "launch_dir"
general_key_transform_file = "transform_file"
general_key_source_file = "source_file"
general_key_source_dir = "source_dir"
general_key_dlc = "dlc"
general_key_update = "update"
general_key_extra = "extra"
general_keys_list_keys = [
    general_key_files,
    general_key_dlc,
    general_key_update,
    general_key_extra
]

# Computer json keys
computer_key_installer_exe = "installer_exe"
computer_key_installer_dos_exe = "installer_dos_exe"
computer_key_installer_type = "installer_type"
computer_key_disc_type = "disc_type"
computer_key_main_game_exe = "main_game_exe"
computer_key_main_game_exe_cwd = "main_game_exe_cwd"
computer_key_main_game_exe_args = "main_game_exe_args"
computer_key_main_game_dos_exe = "main_game_dos_exe"
computer_key_main_game_dos_exe_cwd = "main_game_dos_exe_cwd"
computer_key_main_game_dos_exe_args = "main_game_dos_exe_args"
computer_key_main_game_win31_exe = "main_game_win31_exe"
computer_key_main_game_win31_exe_cwd = "main_game_win31_exe_cwd"
computer_key_main_game_win31_exe_args = "main_game_win31_exe_args"
computer_key_dependencies = "dependencies"
computer_key_source_dir = "source_dir"
computer_key_source_file = "source_file"
computer_key_base_name = "base_name"
computer_key_regular_name = "regular_name"
computer_key_supercategory = "supercategory"
computer_key_category = "category"
computer_key_subcategory = "subcategory"
computer_key_platform = "platform"
computer_key_sandbox = "sandbox"
computer_key_sandbox_sandboxie = "sandboxie"
computer_key_sandbox_wine = "wine"
computer_key_sandbox_wine_tricks = "tricks"
computer_key_sandbox_wine_overrides = "overrides"
computer_key_sandbox_wine_use_dxvk = "use_dxvk"
computer_key_sandbox_wine_use_vkd3d = "use_vkd3d"
computer_key_steps = "steps"
computer_key_steps_preinstall = "preinstall"
computer_key_steps_postinstall = "postinstall"
computer_key_sync = "sync"
computer_key_sync_search = "search"
computer_key_sync_data = "data"
computer_key_registry = "registry"
computer_key_registry_keep_setup = "keep_setup"
computer_key_registry_setup_keys = "setup_keys"
computer_key_winver = "winver"
computer_key_is_32_bit = "is_32_bit"
computer_key_is_dos = "is_dos"
computer_key_is_win31 = "is_win31"
computer_key_is_scumm = "is_scumm"
computer_keys_list_keys = [
    computer_key_installer_exe,
    computer_key_installer_dos_exe,
    computer_key_main_game_exe,
    computer_key_main_game_dos_exe,
    computer_key_main_game_win31_exe,
    computer_key_dependencies
]
computer_keys_dict_keys = [
    computer_key_main_game_exe_cwd,
    computer_key_main_game_exe_args,
    computer_key_main_game_dos_exe_cwd,
    computer_key_main_game_dos_exe_args,
    computer_key_main_game_win31_exe_cwd,
    computer_key_main_game_win31_exe_args,
    computer_key_sandbox,
    computer_key_steps,
    computer_key_sync,
    computer_key_registry
]
computer_keys_bool_keys = [
    computer_key_is_32_bit,
    computer_key_is_dos,
    computer_key_is_win31,
    computer_key_is_scumm
]
computer_keys_str_keys = [
    computer_key_installer_type,
    computer_key_disc_type,
    computer_key_winver
]

# Filter keys
filter_key_launchable_only = "launchable_only"
filter_bool_keys = [
    filter_key_launchable_only
]
