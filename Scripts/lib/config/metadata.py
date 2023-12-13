# Imports
import os
import sys
import collections

# Metadata formats
metadata_format_gamelist = "gamelist"
metadata_format_pegasus = "pegasus"
metadata_formats = [
    metadata_format_gamelist,
    metadata_format_pegasus
]

# Metadata sources
metadata_source_thegamesdb = "thegamesdb"
metadata_source_gamefaqs = "gamefaqs"
metadata_source_itchio = "itchio"

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

# Json keys
general_key_files = "files"
general_key_launch_name = "launch_name"
general_key_launch_file = "launch_file"
general_key_launch_dir = "launch_dir"
general_key_transform_file = "transform_file"
general_key_dlc = "dlc"
general_key_update = "update"
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
computer_key_dlc = "dlc"
computer_key_update = "update"
computer_key_extra = "extra"
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
computer_keys_list_type = [
    computer_key_installer_exe,
    computer_key_installer_dos_exe,
    computer_key_main_game_exe,
    computer_key_main_game_dos_exe,
    computer_key_main_game_win31_exe,
    computer_key_dependencies,
    computer_key_dlc,
    computer_key_update,
    computer_key_extra
]
computer_keys_dict_type = [
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
computer_keys_bool_type = [
    computer_key_is_32_bit,
    computer_key_is_dos,
    computer_key_is_win31,
    computer_key_is_scumm
]
computer_keys_str_type = [
    computer_key_installer_type,
    computer_key_disc_type,
    computer_key_winver
]

# Metadata filter keys
filter_launchable_only = "launchable_only"
filter_bool_keys = [
    filter_launchable_only
]

# Game type weights
gametype_counter = 0
gametype_weights = collections.OrderedDict()
gametype_weights[".m3u"] = gametype_counter; gametype_counter += 1          # Playlist
gametype_weights[".json"] = gametype_counter; gametype_counter += 1         # Json
gametype_weights[".exe"] = gametype_counter; gametype_counter += 1          # Windows executable
gametype_weights[".msi"] = gametype_counter; gametype_counter += 1          # Windows installer
gametype_weights[".apk"] = gametype_counter; gametype_counter += 1          # Google Android
gametype_weights[".ipa"] = gametype_counter; gametype_counter += 1          # Apple iOS
gametype_weights[".img"] = gametype_counter; gametype_counter += 1          # Apple MacOS 8
gametype_weights[".adf"] = gametype_counter; gametype_counter += 1          # Commodore Amiga - Disk
gametype_weights[".g64"] = gametype_counter; gametype_counter += 1          # Commodore 64 - G64
gametype_weights[".crt"] = gametype_counter; gametype_counter += 1          # Commodore 64 - Cartridge
gametype_weights[".tap"] = gametype_counter; gametype_counter += 1          # Commodore 64 - Tape
gametype_weights[".ipf"] = gametype_counter; gametype_counter += 1          # Commodore 64 - Disk
gametype_weights[".lnx"] = gametype_counter; gametype_counter += 1          # Atari Lynx
gametype_weights[".nes"] = gametype_counter; gametype_counter += 1          # Nintendo NES
gametype_weights[".sfc"] = gametype_counter; gametype_counter += 1          # Nintendo SNES
gametype_weights[".gba"] = gametype_counter; gametype_counter += 1          # Nintendo GBA
gametype_weights[".nds"] = gametype_counter; gametype_counter += 1          # Nintendo DS/i
gametype_weights[".trim.3ds"] = gametype_counter; gametype_counter += 1     # Nintendo 3DS
gametype_weights[".trim.xci"] = gametype_counter; gametype_counter += 1     # Nintendo Switch Cartridge
gametype_weights[".nsp"] = gametype_counter; gametype_counter += 1          # Nintendo Swith eShop
gametype_weights[".rvz"] = gametype_counter; gametype_counter += 1          # Nintendo Wii/Gamecube
gametype_weights[".iso.wux"] = gametype_counter; gametype_counter += 1      # Nintendo Wii U Disc
gametype_weights[".wua"] = gametype_counter; gametype_counter += 1          # Nintendo Wii U eShop
gametype_weights[".cue"] = gametype_counter; gametype_counter += 1          # General disc - CUE
gametype_weights[".chd"] = gametype_counter; gametype_counter += 1          # General disc - CHD
gametype_weights[".ccd"] = gametype_counter; gametype_counter += 1          # General disc - CCD
gametype_weights[".cdi"] = gametype_counter; gametype_counter += 1          # General disc - CDI
gametype_weights[".pkg"] = gametype_counter; gametype_counter += 1          # Sony PSN Package
gametype_weights[".txt"] = gametype_counter; gametype_counter += 1          # General index
gametype_weights[".zip"] = gametype_counter; gametype_counter += 1          # Zip archive

# Other game types
gametype_weight_else = 100

# Cookie file
itchio_cookie_filename = "itchio.cookie.txt"
