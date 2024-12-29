# Imports
import os
import sys

# Local imports
from . import categories
from . import types

# Preset option groups
presets_option_groups = {}

# Backup_Microsoft
presets_option_groups[types.PresetOptionGroupType.BACKUP_MICROSOFT] = {
    "supercategory": categories.Supercategory.ROMS,
    "category": categories.Category.MICROSOFT
}

# Backup_NintendoGen
presets_option_groups[types.PresetOptionGroupType.BACKUP_NINTENDOGEN] = {
    "supercategory": categories.Supercategory.ROMS,
    "category": categories.Category.NINTENDO,
    "subcategories": [
        categories.Subcategory.NINTENDO_3DS,
        categories.Subcategory.NINTENDO_3DS_APPS,
        categories.Subcategory.NINTENDO_3DS_ESHOP,
        categories.Subcategory.NINTENDO_64,
        categories.Subcategory.NINTENDO_DS,
        categories.Subcategory.NINTENDO_DSI,
        categories.Subcategory.NINTENDO_FAMICOM,
        categories.Subcategory.NINTENDO_GAME_BOY,
        categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE,
        categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE_EREADER,
        categories.Subcategory.NINTENDO_GAME_BOY_COLOR,
        categories.Subcategory.NINTENDO_GAMECUBE,
        categories.Subcategory.NINTENDO_NES,
        categories.Subcategory.NINTENDO_SNES,
        categories.Subcategory.NINTENDO_SNES_MSU1,
        categories.Subcategory.NINTENDO_SUPER_FAMICOM,
        categories.Subcategory.NINTENDO_SUPER_GAME_BOY,
        categories.Subcategory.NINTENDO_SUPER_GAME_BOY_COLOR,
        categories.Subcategory.NINTENDO_VIRTUAL_BOY,
        categories.Subcategory.NINTENDO_WII,
        categories.Subcategory.NINTENDO_WII_U,
        categories.Subcategory.NINTENDO_WII_U_ESHOP
    ]
}

# Backup_NintendoSwitch
presets_option_groups[types.PresetOptionGroupType.BACKUP_NINTENDOSWITCH] = {
    "supercategory": categories.Supercategory.ROMS,
    "category": categories.Category.NINTENDO,
    "subcategories": [
        categories.Subcategory.NINTENDO_SWITCH,
        categories.Subcategory.NINTENDO_SWITCH_ESHOP
    ]
}

# Backup_OtherGen
presets_option_groups[types.PresetOptionGroupType.BACKUP_OTHERGEN] = {
    "supercategory": categories.Supercategory.ROMS,
    "category": categories.Category.OTHER
}

# Backup_SonyGen
presets_option_groups[types.PresetOptionGroupType.BACKUP_SONYGEN] = {
    "supercategory": categories.Supercategory.ROMS,
    "category": categories.Category.SONY,
    "subcategories": [
        categories.Subcategory.SONY_PLAYSTATION,
        categories.Subcategory.SONY_PLAYSTATION_2,
        categories.Subcategory.SONY_PLAYSTATION_PORTABLE,
        categories.Subcategory.SONY_PLAYSTATION_PORTABLE_VIDEO,
        categories.Subcategory.SONY_PLAYSTATION_VITA
    ]
}

# Backup_SonyPS3
presets_option_groups[types.PresetOptionGroupType.BACKUP_SONYPS3] = {
    "supercategory": categories.Supercategory.ROMS,
    "category": categories.Category.SONY,
    "subcategories": [
        categories.Subcategory.SONY_PLAYSTATION_3
    ]
}

# Backup_SonyPS4
presets_option_groups[types.PresetOptionGroupType.BACKUP_SONYPS4] = {
    "supercategory": categories.Supercategory.ROMS,
    "category": categories.Category.SONY,
    "subcategories": [
        categories.Subcategory.SONY_PLAYSTATION_4
    ]
}

# Backup_SonyPSN
presets_option_groups[types.PresetOptionGroupType.BACKUP_SONYPSN] = {
    "supercategory": categories.Supercategory.ROMS,
    "category": categories.Category.SONY,
    "subcategories": [
        categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS3,
        categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS4,
        categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSP,
        categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSPM,
        categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSV
    ]
}
