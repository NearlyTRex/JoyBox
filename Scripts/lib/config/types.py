# Imports
import os
import sys

# Metadata formats
metadata_format_type_pegasus = "pegasus"
metadata_format_types = [
    metadata_format_type_pegasus
]

# Metadata sources
metadata_source_type_thegamesdb = "thegamesdb"
metadata_source_type_gamefaqs = "gamefaqs"
metadata_source_type_itchio = "itchio"

# Addon types
addon_type_dlc = "dlc"
addon_type_updates = "updates"

# Launch types
launch_type_none = "no_launcher"
launch_type_file = "launch_file"
launch_type_name = "launch_name"

# Units
unit_type_seconds = "seconds"
unit_type_minutes = "minutes"
unit_type_hours = "hours"

# Prefixes
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
sync_type_gdrive = "gdrive"

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
