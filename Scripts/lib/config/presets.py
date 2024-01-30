# Imports
import os
import sys

# Local imports
from . import categories
from . import types

# Presets
presets_options = {}

# Backup_Microsoft
presets_options[types.preset_type_backup_microsoft] = {
    "supercategory": categories.game_supercategory_roms,
    "category": categories.game_category_microsoft
}

# Backup_NintendoGen
presets_options[types.preset_type_backup_nintendogen] = {
    "supercategory": categories.game_supercategory_roms,
    "category": categories.game_category_nintendo,
    "subcategories": [
        categories.game_subcategory_nintendo_3ds,
        categories.game_subcategory_nintendo_3ds_apps,
        categories.game_subcategory_nintendo_3ds_eshop,
        categories.game_subcategory_nintendo_64,
        categories.game_subcategory_nintendo_ds,
        categories.game_subcategory_nintendo_dsi,
        categories.game_subcategory_nintendo_famicom,
        categories.game_subcategory_nintendo_game_boy,
        categories.game_subcategory_nintendo_game_boy_advance,
        categories.game_subcategory_nintendo_game_boy_advance_ereader,
        categories.game_subcategory_nintendo_game_boy_color,
        categories.game_subcategory_nintendo_gamecube,
        categories.game_subcategory_nintendo_nes,
        categories.game_subcategory_nintendo_snes,
        categories.game_subcategory_nintendo_super_famicom,
        categories.game_subcategory_nintendo_super_game_boy,
        categories.game_subcategory_nintendo_super_game_boy_color,
        categories.game_subcategory_nintendo_virtual_boy,
        categories.game_subcategory_nintendo_wii,
        categories.game_subcategory_nintendo_wii_u,
        categories.game_subcategory_nintendo_wii_u_eshop
    ]
}

# Backup_NintendoSwitch
presets_options[types.preset_type_backup_nintendoswitch] = {
    "supercategory": categories.game_supercategory_roms,
    "category": categories.game_category_nintendo,
    "subcategories": [
        categories.game_subcategory_nintendo_switch,
        categories.game_subcategory_nintendo_switch_eshop
    ]
}

# Backup_OtherGen
presets_options[types.preset_type_backup_othergen] = {
    "supercategory": categories.game_supercategory_roms,
    "category": categories.game_category_other
}

# Backup_SonyGen
presets_options[types.preset_type_backup_sonygen] = {
    "supercategory": categories.game_supercategory_roms,
    "category": categories.game_category_sony,
    "subcategories": [
        categories.game_subcategory_sony_playstation,
        categories.game_subcategory_sony_playstation_2,
        categories.game_subcategory_sony_playstation_portable,
        categories.game_subcategory_sony_playstation_portable_video,
        categories.game_subcategory_sony_playstation_vita
    ]
}

# Backup_SonyPS3
presets_options[types.preset_type_backup_sonyps3] = {
    "supercategory": categories.game_supercategory_roms,
    "category": categories.game_category_sony,
    "subcategories": [
        categories.game_subcategory_sony_playstation_3
    ]
}

# Backup_SonyPS4
presets_options[types.preset_type_backup_sonyps4] = {
    "supercategory": categories.game_supercategory_roms,
    "category": categories.game_category_sony,
    "subcategories": [
        categories.game_subcategory_sony_playstation_4
    ]
}

# Backup_SonyPSN
presets_options[types.preset_type_backup_sonypsn] = {
    "supercategory": categories.game_supercategory_roms,
    "category": categories.game_category_sony,
    "subcategories": [
        categories.game_subcategory_sony_playstation_network_ps3,
        categories.game_subcategory_sony_playstation_network_ps4,
        categories.game_subcategory_sony_playstation_network_psp,
        categories.game_subcategory_sony_playstation_network_pspm,
        categories.game_subcategory_sony_playstation_network_psv
    ]
}
