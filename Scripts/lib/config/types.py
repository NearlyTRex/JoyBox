# Imports
import os
import sys

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

# Transform types
transform_exe_to_install = "exe_to_install"
transform_exe_to_raw_plain = "exe_to_raw_plain"
transform_chd_to_iso = "chd_to_iso"
transform_iso_to_xiso = "iso_to_xiso"
transform_iso_to_raw_plain = "iso_to_raw_plain"
transform_iso_to_raw_ps3 = "iso_to_raw_ps3"
transform_pkg_to_raw_ps3 = "pkg_to_raw_ps3"
transform_pkg_to_raw_psv = "pkg_to_raw_psv"

# Addon types
addon_dlc = "dlc"
addon_updates = "updates"

# Launch types
launch_none = "no_launcher"
launch_file = "launch_file"
launch_name = "launch_name"

# Units
unit_type_seconds = "seconds"
unit_type_minutes = "minutes"
unit_type_hours = "hours"

# Prefixes
prefix_name_default = "Default"
prefix_name_tool = "Tool"
prefix_name_emulator = "Emulator"
prefix_name_game = "Game"
prefix_name_setup = "Setup"

# Save formats
save_format_general = "General"
save_format_wine = "Wine"
save_format_sandboxie = "Sandboxie"

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

# Installer formats
installer_format_inno = "inno"
installer_format_nsis = "nsis"
installer_format_ins = "installshield"
installer_format_7zip = "7zip"
installer_format_winrar = "winrar"
installer_format_unknown = "unknown"
