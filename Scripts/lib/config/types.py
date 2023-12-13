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
