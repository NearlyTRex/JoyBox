# Imports
import os
import sys

# Locker types
locker_type_artwork = "Artwork"
locker_type_books = "Books"
locker_type_development = "Development"
locker_type_documents = "Documents"
locker_type_gaming = "Gaming"
locker_type_movies = "Movies"
locker_type_music = "Music"
locker_type_photos = "Photos"
locker_type_programs = "Programs"

# Passphrase types
passphrase_type_none = "None"
passphrase_type_general = "General"
passphrase_type_locker = "Locker"
passphrase_types = [
    passphrase_type_none,
    passphrase_type_general,
    passphrase_type_locker
]

# Backup types
backup_type_copy = "copy"
backup_type_archive = "archive"
backup_types = [
    backup_type_copy,
    backup_type_archive
]

# Source types
source_type_local = "local"
source_type_remote = "remote"
source_types = [
    source_type_local,
    source_type_remote
]

# Source file types
source_file_type_input = "input"
source_file_type_stored = "stored"
source_file_types = [
    source_file_type_input,
    source_file_type_stored
]

# Json generation types
json_generation_type_custom = "custom"
json_generation_type_standard = "standard"
json_generation_type_store = "store"
json_generation_types = [
    json_generation_type_custom,
    json_generation_type_standard
]

# Steam id formats
steam_id_format_64 = "steamid64"
steam_id_format_3l = "steamid3l"
steam_id_format_3s = "steamid3s"
steam_id_format_cl = "steamidcl"
steam_id_format_cs = "steamidcs"
steam_id_formats = [
    steam_id_format_64,
    steam_id_format_3l,
    steam_id_format_3s,
    steam_id_format_cl,
    steam_id_format_cs
]

# Steam branch formats
steam_branch_format_public = "public"
steam_branch_formats = [
    steam_branch_format_public
]

# Metadata format types
metadata_format_type_pegasus = "pegasus"
metadata_format_types = [
    metadata_format_type_pegasus
]

# Metadata source types
metadata_source_type_thegamesdb = "thegamesdb"
metadata_source_type_gamefaqs = "gamefaqs"
metadata_source_type_store = "store"
metadata_source_types = [
    metadata_source_type_thegamesdb,
    metadata_source_type_gamefaqs,
    metadata_source_type_store
]

# Addon types
addon_type_dlc = "dlc"
addon_type_updates = "updates"

# Launch types
launch_type_none = "no_launcher"
launch_type_file = "launch_file"
launch_type_name = "launch_name"

# Unit types
unit_type_seconds = "seconds"
unit_type_minutes = "minutes"
unit_type_hours = "hours"

# Prefix types
prefix_type_default = "Default"
prefix_type_tool = "Tool"
prefix_type_emulator = "Emulator"
prefix_type_game = "Game"
prefix_type_setup = "Setup"

# Save types
save_type_general = "General"
save_type_wine = "Wine"
save_type_sandboxie = "Sandboxie"

# Capture types
capture_type_none = "none"
capture_type_screenshot = "screenshot"
capture_type_video = "video"

# Disc types
disc_type_normal = "normal"
disc_type_macwin = "macwin"

# Asset types
asset_type_background = "Background"
asset_type_boxback = "BoxBack"
asset_type_boxfront = "BoxFront"
asset_type_label = "Label"
asset_type_screenshot = "Screenshot"
asset_type_video = "Video"
asset_types_all = [
    asset_type_background,
    asset_type_boxback,
    asset_type_boxfront,
    asset_type_label,
    asset_type_screenshot,
    asset_type_video
]
asset_types_min = [
    asset_type_background,
    asset_type_boxback,
    asset_type_boxfront,
    asset_type_screenshot
]
asset_types_image = [
    asset_type_background,
    asset_type_boxback,
    asset_type_boxfront,
    asset_type_label,
    asset_type_screenshot
]
asset_types_movie = [
    asset_type_video
]
asset_type_extensions = {
    asset_type_background: ".jpg",
    asset_type_boxback: ".jpg",
    asset_type_boxfront: ".jpg",
    asset_type_label: ".png",
    asset_type_screenshot: ".jpg",
    asset_type_video: ".mp4",
}

# Message types
message_type_general = "general"
message_type_ok = "ok"
message_type_yes_no = "yesno"
message_type_cancel = "cancel"
message_type_ok_cancel = "ok_cancel"
message_type_error = "error"
message_type_auto_close = "auto_close"
message_type_get_text = "get_text"
message_type_get_file = "get_file"
message_type_get_folder = "get_folder"

# Installer types
installer_type_inno = "inno"
installer_type_nsis = "nsis"
installer_type_ins = "installshield"
installer_type_7zip = "7zip"
installer_type_winrar = "winrar"
installer_type_unknown = "unknown"

# Release types
release_type_program = "program"
release_type_installer = "installer"
release_type_archive = "archive"

# Sync types
sync_type_gdrive = "drive"
sync_type_b2 = "b2"

# Archive types
archive_type_zip = "zip"
archive_type_7z = "7z"

# Mime types
mime_types_zip = ["application/zip"]
mime_types_7z = ["application/x-7z-compressed"]
mime_types_rar = ["application/x-rar-compressed"]
mime_types_tarball = ["application/x-gzip", "application/gzip"]
mime_types_exe = ["application/x-dosexec"]
mime_types_appimage = ["application/x-executable"]

# Preset types
preset_type_backup_microsoft = "Backup_Microsoft"
preset_type_backup_nintendogen = "Backup_NintendoGen"
preset_type_backup_nintendoswitch = "Backup_NintendoSwitch"
preset_type_backup_othergen = "Backup_OtherGen"
preset_type_backup_sonygen = "Backup_SonyGen"
preset_type_backup_sonyps3 = "Backup_SonyPS3"
preset_type_backup_sonyps4 = "Backup_SonyPS4"
preset_type_backup_sonypsn = "Backup_SonyPSN"
preset_types = [
    preset_type_backup_microsoft,
    preset_type_backup_nintendogen,
    preset_type_backup_nintendoswitch,
    preset_type_backup_othergen,
    preset_type_backup_sonygen,
    preset_type_backup_sonyps3,
    preset_type_backup_sonyps4,
    preset_type_backup_sonypsn
]

# Store types
store_type_amazon = "Amazon"
store_type_gog = "GOG"
store_type_epic = "Epic"
store_type_itchio = "Itchio"
store_type_steam = "Steam"
store_types = [
    store_type_amazon,
    store_type_gog,
    store_type_epic,
    store_type_itchio,
    store_type_steam
]

# Store action types
store_action_type_login = "login"
store_action_type_display_purchases = "display_purchases"
store_action_type_import_purchases = "import_purchases"
store_action_type_install_game = "install_game"
store_action_type_launch_game = "launch_game"
store_action_type_download_game = "download_game"
store_action_type_download_asset = "download_asset"
store_action_type_update_json = "update_json"
store_action_type_update_metadata = "update_metadata"
store_action_type_check_versions = "check_versions"
store_action_type_export_saves = "export_saves"
store_action_type_import_saves = "import_saves"
store_action_types = [
    store_action_type_login,
    store_action_type_display_purchases,
    store_action_type_import_purchases,
    store_action_type_install_game,
    store_action_type_launch_game,
    store_action_type_download_game,
    store_action_type_download_asset,
    store_action_type_update_json,
    store_action_type_update_metadata,
    store_action_type_check_versions,
    store_action_type_export_saves,
    store_action_type_import_saves
]

# Store identifier types
store_identifier_type_info = "info"
store_identifier_type_install = "install"
store_identifier_type_launch = "launch"
store_identifier_type_download = "download"
store_identifier_type_asset = "asset"
store_identifier_type_metadata = "metadata"
store_identifier_types = [
    store_identifier_type_info,
    store_identifier_type_install,
    store_identifier_type_launch,
    store_identifier_type_download,
    store_identifier_type_asset,
    store_identifier_type_metadata
]

# Playlist types
playlist_type_tree = "tree"
playlist_type_local = "local"
playlist_types = [
    playlist_type_tree,
    playlist_type_local
]

# Merge types
merge_type_replace = "replace"
merge_type_additive = "additive"
merge_type_safereplace = "safereplace"
merge_type_safeadditive = "safeadditive"
merge_types = [
    merge_type_replace,
    merge_type_additive,
    merge_type_safereplace,
    merge_type_safeadditive
]

# Web driver types
web_driver_type_firefox = "firefox"
web_driver_type_chrome = "chrome"
web_driver_types = [
    web_driver_type_firefox,
    web_driver_type_chrome
]

# Image types
image_type_jpeg = "JPEG"
image_type_png = "PNG"
image_types = [
    image_type_jpeg,
    image_type_png
]
