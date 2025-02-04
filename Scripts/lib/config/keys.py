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
platform_key_merge_json = "merge_json"

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
metadata_key_url = "url"
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
metadata_keys_downloadable = [
    metadata_key_description,
    metadata_key_genre,
    metadata_key_coop,
    metadata_key_developer,
    metadata_key_publisher,
    metadata_key_players,
    metadata_key_release
]
metadata_keys_all = [
    metadata_key_game,
    metadata_key_platform,
    metadata_key_supercategory,
    metadata_key_category,
    metadata_key_subcategory,
    metadata_key_file,
    metadata_key_description,
    metadata_key_url,
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

# Search keys
search_result_key_id = "id"
search_result_key_title = "title"
search_result_key_description = "description"
search_result_key_url = "url"
search_result_key_date = "date"
search_result_key_relevance = "relevance"
search_result_key_data = "data"

# Asset keys
asset_key_mime = "mime"
asset_key_width = "width"
asset_key_height = "height"
asset_key_duration = "duration"

# Computer program keys
program_key_exe = "exe"
program_key_cwd = "cwd"
program_key_args = "args"
program_key_winver = "winver"
program_key_is_32_bit = "is_32_bit"
program_key_is_dos = "is_dos"
program_key_is_win31 = "is_win31"
program_key_is_scumm = "is_scumm"
program_key_tricks = "tricks"
program_key_overrides = "overrides"
program_key_desktop = "desktop"
program_key_use_virtual_desktop = "use_virtual_desktop"
program_key_disc_type = "disc_type"
program_key_installer_type = "installer_type"
program_key_serial = "serial"

# General json keys
json_key_launch_name = "launch_name"
json_key_launch_file = "launch_file"
json_key_launch_dir = "launch_dir"
json_key_transform_file = "transform_file"
json_key_key_file = "key_file"
json_key_files = "files"
json_key_dlc = "dlc"
json_key_update = "update"
json_key_extra = "extra"
json_key_dependencies = "dependencies"

# Virtual json keys
json_key_metadata = "metadata"
json_key_save_dir = "save_dir"
json_key_general_save_dir = "general_save_dir"
json_key_local_cache_dir = "local_cache_dir"
json_key_remote_cache_dir = "remote_cache_dir"
json_key_local_rom_dir = "local_rom_dir"
json_key_remote_rom_dir = "remote_rom_dir"

# Computer json keys
json_key_amazon = "amazon"
json_key_disc = "disc"
json_key_epic = "epic"
json_key_gog = "gog"
json_key_humble = "humble"
json_key_itchio = "itchio"
json_key_legacy = "legacy"
json_key_puppetcombo = "puppetcombo"
json_key_redcandle = "redcandle"
json_key_squareenix = "squareenix"
json_key_steam = "steam"
json_key_zoom = "zoom"
json_key_store_appid = "appid"
json_key_store_appname = "appname"
json_key_store_appurl = "appurl"
json_key_store_branchid = "branchid"
json_key_store_builddate = "builddate"
json_key_store_buildid = "buildid"
json_key_store_name = "name"
json_key_store_controller_support = "controller_support"
json_key_store_installdir = "installdir"
json_key_store_paths = "paths"
json_key_store_keys = "keys"
json_key_store_launch = "launch"
json_key_store_setup = "setup"
json_key_store_setup_install = "install"
json_key_store_setup_preinstall = "preinstall"
json_key_store_setup_postinstall = "postinstall"
json_keys_store = [
    json_key_amazon,
    json_key_disc,
    json_key_epic,
    json_key_gog,
    json_key_humble,
    json_key_itchio,
    json_key_legacy,
    json_key_puppetcombo,
    json_key_redcandle,
    json_key_squareenix,
    json_key_steam,
    json_key_zoom
]
json_keys_store_appdata = [
    json_key_store_appid,
    json_key_store_appname,
    json_key_store_appurl
]
json_keys_store_subdata = [
    json_key_store_appid,
    json_key_store_appname,
    json_key_store_appurl,
    json_key_store_branchid,
    json_key_store_builddate,
    json_key_store_buildid,
    json_key_store_name,
    json_key_store_controller_support,
    json_key_store_installdir,
    json_key_store_paths,
    json_key_store_keys,
    json_key_store_launch,
    json_key_store_setup
]

# Json key defaults
json_key_defaults = []
json_key_defaults.append({"key": json_key_launch_name, "default": None})
json_key_defaults.append({"key": json_key_launch_file, "default": []})
json_key_defaults.append({"key": json_key_launch_dir, "default": None})
json_key_defaults.append({"key": json_key_transform_file, "default": []})
json_key_defaults.append({"key": json_key_key_file, "default": []})
json_key_defaults.append({"key": json_key_files, "default": []})
json_key_defaults.append({"key": json_key_dlc, "default": []})
json_key_defaults.append({"key": json_key_update, "default": []})
json_key_defaults.append({"key": json_key_extra, "default": []})
json_key_defaults.append({"key": json_key_dependencies, "default": []})
json_key_defaults.append({"key": json_key_amazon, "default": {}})
json_key_defaults.append({"key": json_key_disc, "default": {}})
json_key_defaults.append({"key": json_key_epic, "default": {}})
json_key_defaults.append({"key": json_key_gog, "default": {}})
json_key_defaults.append({"key": json_key_humble, "default": {}})
json_key_defaults.append({"key": json_key_itchio, "default": {}})
json_key_defaults.append({"key": json_key_legacy, "default": {}})
json_key_defaults.append({"key": json_key_puppetcombo, "default": {}})
json_key_defaults.append({"key": json_key_redcandle, "default": {}})
json_key_defaults.append({"key": json_key_squareenix, "default": {}})
json_key_defaults.append({"key": json_key_steam, "default": {}})
json_key_defaults.append({"key": json_key_zoom, "default": {}})
for json_key in json_keys_store:
    json_key_defaults.append({"key": (json_key, json_key_store_appid), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_appname), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_appurl), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_branchid), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_builddate), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_buildid), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_name), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_controller_support), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_installdir), "default": ""})
    json_key_defaults.append({"key": (json_key, json_key_store_paths), "default": []})
    json_key_defaults.append({"key": (json_key, json_key_store_keys), "default": []})
    json_key_defaults.append({"key": (json_key, json_key_store_launch), "default": {}})
    json_key_defaults.append({"key": (json_key, json_key_store_setup), "default": {}})

# Filter keys
filter_key_launchable_only = "launchable_only"
keys_filter_keys = [
    filter_key_launchable_only
]
