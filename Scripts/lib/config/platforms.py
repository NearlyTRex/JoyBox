# Imports
import os
import sys

# Local imports
from . import categories
from . import keys
from . import types

# Platforms
platforms = {}

# Computer platforms
platform_computer_amazon_games = categories.game_category_computer + " - " + categories.game_subcategory_amazon_games
platform_computer_disc = categories.game_category_computer + " - " + categories.game_subcategory_disc
platform_computer_epic_games = categories.game_category_computer + " - " + categories.game_subcategory_epic_games
platform_computer_gog = categories.game_category_computer + " - " + categories.game_subcategory_gog
platform_computer_humble_bundle = categories.game_category_computer + " - " + categories.game_subcategory_humble_bundle
platform_computer_itchio = categories.game_category_computer + " - " + categories.game_subcategory_itchio
platform_computer_puppet_combo = categories.game_category_computer + " - " + categories.game_subcategory_puppet_combo
platform_computer_red_candle = categories.game_category_computer + " - " + categories.game_subcategory_red_candle
platform_computer_square_enix = categories.game_category_computer + " - " + categories.game_subcategory_square_enix
platform_computer_steam = categories.game_category_computer + " - " + categories.game_subcategory_steam
platform_computer_zoom = categories.game_category_computer + " - " + categories.game_subcategory_zoom

# Transform platforms
transform_platforms = [

    # Computer
    platform_computer_amazon_games,
    platform_computer_disc,
    platform_computer_epic_games,
    platform_computer_gog,
    platform_computer_humble_bundle,
    platform_computer_itchio,
    platform_computer_puppet_combo,
    platform_computer_red_candle,
    platform_computer_square_enix,
    platform_computer_steam,
    platform_computer_zoom,

    # Microsoft
    categories.game_subcategory_microsoft_xbox,
    categories.game_subcategory_microsoft_xbox_360,

    # Sony
    categories.game_subcategory_sony_playstation_3,
    categories.game_subcategory_sony_playstation_network_ps3,
    categories.game_subcategory_sony_playstation_network_psv
]

# Letter platforms
letter_platforms = [

    # Computer
    platform_computer_amazon_games,
    platform_computer_disc,
    platform_computer_epic_games,
    platform_computer_gog,
    platform_computer_humble_bundle,
    platform_computer_itchio,
    platform_computer_puppet_combo,
    platform_computer_red_candle,
    platform_computer_square_enix,
    platform_computer_steam,
    platform_computer_zoom
]

######################################################################################

###########################################################
# Computer - Amazon Games
###########################################################
computer_amazon_games = {}
computer_amazon_games[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_amazon_games[keys.platform_key_category] = categories.game_category_computer
computer_amazon_games[keys.platform_key_subcategory] = categories.game_subcategory_amazon_games
computer_amazon_games[keys.platform_key_addons] = []
computer_amazon_games[keys.platform_key_launcher] = [types.launch_type_file]
computer_amazon_games[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file,
    keys.json_key_store_builddate,
    keys.json_key_store_buildid,
    keys.json_key_store_name,
    keys.json_key_store_controller_support,
    keys.json_key_store_installdir
]
computer_amazon_games[keys.platform_key_fillonce_json] = [
    keys.json_key_amazon,
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
platforms[platform_computer_amazon_games] = computer_amazon_games

###########################################################
# Computer - Disc
###########################################################
computer_disc = {}
computer_disc[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_disc[keys.platform_key_category] = categories.game_category_computer
computer_disc[keys.platform_key_subcategory] = categories.game_subcategory_disc
computer_disc[keys.platform_key_addons] = []
computer_disc[keys.platform_key_launcher] = [types.launch_type_file]
computer_disc[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_transform_file
]
computer_disc[keys.platform_key_fillonce_json] = []
platforms[platform_computer_disc] = computer_disc

###########################################################
# Computer - Epic Games
###########################################################
computer_epic_games = {}
computer_epic_games[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_epic_games[keys.platform_key_category] = categories.game_category_computer
computer_epic_games[keys.platform_key_subcategory] = categories.game_subcategory_epic_games
computer_epic_games[keys.platform_key_addons] = []
computer_epic_games[keys.platform_key_launcher] = [types.launch_type_file]
computer_epic_games[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file,
    keys.json_key_store_builddate,
    keys.json_key_store_buildid,
    keys.json_key_store_name,
    keys.json_key_store_controller_support,
    keys.json_key_store_installdir
]
computer_epic_games[keys.platform_key_fillonce_json] = [
    keys.json_key_epic,
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
platforms[platform_computer_epic_games] = computer_epic_games

###########################################################
# Computer - GOG
###########################################################
computer_gog = {}
computer_gog[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_gog[keys.platform_key_category] = categories.game_category_computer
computer_gog[keys.platform_key_subcategory] = categories.game_subcategory_gog
computer_gog[keys.platform_key_addons] = []
computer_gog[keys.platform_key_launcher] = [types.launch_type_file]
computer_gog[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file,
    keys.json_key_store_builddate,
    keys.json_key_store_buildid,
    keys.json_key_store_name,
    keys.json_key_store_controller_support,
    keys.json_key_store_installdir
]
computer_gog[keys.platform_key_fillonce_json] = [
    keys.json_key_gog,
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
platforms[platform_computer_gog] = computer_gog

###########################################################
# Computer - Humble Bundle
###########################################################
computer_humble_bundle = {}
computer_humble_bundle[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_humble_bundle[keys.platform_key_category] = categories.game_category_computer
computer_humble_bundle[keys.platform_key_subcategory] = categories.game_subcategory_humble_bundle
computer_humble_bundle[keys.platform_key_addons] = []
computer_humble_bundle[keys.platform_key_launcher] = [types.launch_type_file]
computer_humble_bundle[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file
]
computer_humble_bundle[keys.platform_key_fillonce_json] = []
platforms[platform_computer_humble_bundle] = computer_humble_bundle

###########################################################
# Computer - Itchio
###########################################################
computer_itchio = {}
computer_itchio[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_itchio[keys.platform_key_category] = categories.game_category_computer
computer_itchio[keys.platform_key_subcategory] = categories.game_subcategory_itchio
computer_itchio[keys.platform_key_addons] = []
computer_itchio[keys.platform_key_launcher] = [types.launch_type_file]
computer_itchio[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file
]
computer_itchio[keys.platform_key_fillonce_json] = []
platforms[platform_computer_itchio] = computer_itchio

###########################################################
# Computer - Puppet Combo
###########################################################
computer_puppet_combo = {}
computer_puppet_combo[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_puppet_combo[keys.platform_key_category] = categories.game_category_computer
computer_puppet_combo[keys.platform_key_subcategory] = categories.game_subcategory_puppet_combo
computer_puppet_combo[keys.platform_key_addons] = []
computer_puppet_combo[keys.platform_key_launcher] = [types.launch_type_file]
computer_puppet_combo[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file
]
computer_puppet_combo[keys.platform_key_fillonce_json] = []
platforms[platform_computer_puppet_combo] = computer_puppet_combo

###########################################################
# Computer - Red Candle
###########################################################
computer_red_candle = {}
computer_red_candle[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_red_candle[keys.platform_key_category] = categories.game_category_computer
computer_red_candle[keys.platform_key_subcategory] = categories.game_subcategory_red_candle
computer_red_candle[keys.platform_key_addons] = []
computer_red_candle[keys.platform_key_launcher] = [types.launch_type_file]
computer_red_candle[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file
]
computer_red_candle[keys.platform_key_fillonce_json] = []
platforms[platform_computer_red_candle] = computer_red_candle

###########################################################
# Computer - Square Enix
###########################################################
computer_square_enix = {}
computer_square_enix[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_square_enix[keys.platform_key_category] = categories.game_category_computer
computer_square_enix[keys.platform_key_subcategory] = categories.game_subcategory_square_enix
computer_square_enix[keys.platform_key_addons] = []
computer_square_enix[keys.platform_key_launcher] = [types.launch_type_file]
computer_square_enix[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file
]
computer_square_enix[keys.platform_key_fillonce_json] = []
platforms[platform_computer_square_enix] = computer_square_enix

###########################################################
# Computer - Steam
###########################################################
computer_steam = {}
computer_steam[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_steam[keys.platform_key_category] = categories.game_category_computer
computer_steam[keys.platform_key_subcategory] = categories.game_subcategory_steam
computer_steam[keys.platform_key_addons] = []
computer_steam[keys.platform_key_launcher] = [types.launch_type_file]
computer_steam[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file,
    keys.json_key_store_builddate,
    keys.json_key_store_buildid,
    keys.json_key_store_name,
    keys.json_key_store_controller_support,
    keys.json_key_store_installdir
]
computer_steam[keys.platform_key_fillonce_json] = [
    keys.json_key_steam,
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
platforms[platform_computer_steam] = computer_steam

###########################################################
# Computer - Zoom
###########################################################
computer_zoom = {}
computer_zoom[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_zoom[keys.platform_key_category] = categories.game_category_computer
computer_zoom[keys.platform_key_subcategory] = categories.game_subcategory_zoom
computer_zoom[keys.platform_key_addons] = []
computer_zoom[keys.platform_key_launcher] = [types.launch_type_file]
computer_zoom[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_installer_exe,
    keys.json_key_transform_file
]
computer_zoom[keys.platform_key_fillonce_json] = []
platforms[platform_computer_zoom] = computer_zoom

######################################################################################

###########################################################
# Microsoft MSX
###########################################################
microsoft_msx = {}
microsoft_msx[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_msx[keys.platform_key_category] = categories.game_category_microsoft
microsoft_msx[keys.platform_key_subcategory] = categories.game_subcategory_microsoft_msx
microsoft_msx[keys.platform_key_addons] = []
microsoft_msx[keys.platform_key_launcher] = [types.launch_type_file]
microsoft_msx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
microsoft_msx[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_microsoft_msx] = microsoft_msx

###########################################################
# Microsoft Xbox
###########################################################
microsoft_xbox = {}
microsoft_xbox[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox[keys.platform_key_subcategory] = categories.game_subcategory_microsoft_xbox
microsoft_xbox[keys.platform_key_addons] = []
microsoft_xbox[keys.platform_key_launcher] = [types.launch_type_file]
microsoft_xbox[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
microsoft_xbox[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
platforms[categories.game_subcategory_microsoft_xbox] = microsoft_xbox

###########################################################
# Microsoft Xbox 360
###########################################################
microsoft_xbox_360 = {}
microsoft_xbox_360[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_360[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_360[keys.platform_key_subcategory] = categories.game_subcategory_microsoft_xbox_360
microsoft_xbox_360[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
microsoft_xbox_360[keys.platform_key_launcher] = [types.launch_type_file]
microsoft_xbox_360[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
microsoft_xbox_360[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
platforms[categories.game_subcategory_microsoft_xbox_360] = microsoft_xbox_360

###########################################################
# Microsoft Xbox 360 GOD
###########################################################
microsoft_xbox_360_god = {}
microsoft_xbox_360_god[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_360_god[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_360_god[keys.platform_key_subcategory] = categories.game_subcategory_microsoft_xbox_360_god
microsoft_xbox_360_god[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
microsoft_xbox_360_god[keys.platform_key_launcher] = [types.launch_type_file]
microsoft_xbox_360_god[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_god[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
platforms[categories.game_subcategory_microsoft_xbox_360_god] = microsoft_xbox_360_god

###########################################################
# Microsoft Xbox 360 XBLA
###########################################################
microsoft_xbox_360_xbla = {}
microsoft_xbox_360_xbla[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_360_xbla[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_360_xbla[keys.platform_key_subcategory] = categories.game_subcategory_microsoft_xbox_360_xbla
microsoft_xbox_360_xbla[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
microsoft_xbox_360_xbla[keys.platform_key_launcher] = [types.launch_type_file]
microsoft_xbox_360_xbla[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_xbla[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
platforms[categories.game_subcategory_microsoft_xbox_360_xbla] = microsoft_xbox_360_xbla

###########################################################
# Microsoft Xbox 360 XIG
###########################################################
microsoft_xbox_360_xig = {}
microsoft_xbox_360_xig[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_360_xig[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_360_xig[keys.platform_key_subcategory] = categories.game_subcategory_microsoft_xbox_360_xig
microsoft_xbox_360_xig[keys.platform_key_addons] = []
microsoft_xbox_360_xig[keys.platform_key_launcher] = [types.launch_type_file]
microsoft_xbox_360_xig[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_xig[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
platforms[categories.game_subcategory_microsoft_xbox_360_xig] = microsoft_xbox_360_xig

###########################################################
# Microsoft Xbox One
###########################################################
microsoft_xbox_one = {}
microsoft_xbox_one[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_one[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_one[keys.platform_key_subcategory] = categories.game_subcategory_microsoft_xbox_one
microsoft_xbox_one[keys.platform_key_addons] = []
microsoft_xbox_one[keys.platform_key_launcher] = [types.launch_type_none]
microsoft_xbox_one[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_one[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_microsoft_xbox_one] = microsoft_xbox_one

###########################################################
# Microsoft Xbox One GOD
###########################################################
microsoft_xbox_one_god = {}
microsoft_xbox_one_god[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_one_god[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_one_god[keys.platform_key_subcategory] = categories.game_subcategory_microsoft_xbox_one_god
microsoft_xbox_one_god[keys.platform_key_addons] = []
microsoft_xbox_one_god[keys.platform_key_launcher] = [types.launch_type_none]
microsoft_xbox_one_god[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_one_god[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_microsoft_xbox_one_god] = microsoft_xbox_one_god

######################################################################################

###########################################################
# Nintendo 3DS
###########################################################
nintendo_3ds = {}
nintendo_3ds[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_3ds[keys.platform_key_category] = categories.game_category_nintendo
nintendo_3ds[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_3ds
nintendo_3ds[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_3ds[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_3ds[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_3ds[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_3ds] = nintendo_3ds

###########################################################
# Nintendo 3DS Apps
###########################################################
nintendo_3ds_apps = {}
nintendo_3ds_apps[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_3ds_apps[keys.platform_key_category] = categories.game_category_nintendo
nintendo_3ds_apps[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_3ds_apps
nintendo_3ds_apps[keys.platform_key_addons] = []
nintendo_3ds_apps[keys.platform_key_launcher] = [types.launch_type_none]
nintendo_3ds_apps[keys.platform_key_autofill_json] = [keys.json_key_files]
nintendo_3ds_apps[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_3ds_apps] = nintendo_3ds_apps

###########################################################
# Nintendo 3DS eShop
###########################################################
nintendo_3ds_eshop = {}
nintendo_3ds_eshop[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_3ds_eshop[keys.platform_key_category] = categories.game_category_nintendo
nintendo_3ds_eshop[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_3ds_eshop
nintendo_3ds_eshop[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_3ds_eshop[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_3ds_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_3ds_eshop[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_3ds_eshop] = nintendo_3ds_eshop

###########################################################
# Nintendo 64
###########################################################
nintendo_64 = {}
nintendo_64[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_64[keys.platform_key_category] = categories.game_category_nintendo
nintendo_64[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_64
nintendo_64[keys.platform_key_addons] = []
nintendo_64[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_64[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_64[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_64] = nintendo_64

###########################################################
# Nintendo DS
###########################################################
nintendo_ds = {}
nintendo_ds[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_ds[keys.platform_key_category] = categories.game_category_nintendo
nintendo_ds[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_ds
nintendo_ds[keys.platform_key_addons] = []
nintendo_ds[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_ds[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_ds[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_ds] = nintendo_ds

###########################################################
# Nintendo DSi
###########################################################
nintendo_dsi = {}
nintendo_dsi[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_dsi[keys.platform_key_category] = categories.game_category_nintendo
nintendo_dsi[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_dsi
nintendo_dsi[keys.platform_key_addons] = []
nintendo_dsi[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_dsi[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_dsi[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_dsi] = nintendo_dsi

###########################################################
# Nintendo Famicom
###########################################################
nintendo_famicom = {}
nintendo_famicom[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_famicom[keys.platform_key_category] = categories.game_category_nintendo
nintendo_famicom[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_famicom
nintendo_famicom[keys.platform_key_addons] = []
nintendo_famicom[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_famicom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_famicom[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_famicom] = nintendo_famicom

###########################################################
# Nintendo Game Boy
###########################################################
nintendo_game_boy = {}
nintendo_game_boy[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_game_boy[keys.platform_key_category] = categories.game_category_nintendo
nintendo_game_boy[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_game_boy
nintendo_game_boy[keys.platform_key_addons] = []
nintendo_game_boy[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_game_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_game_boy] = nintendo_game_boy

###########################################################
# Nintendo Game Boy Advance
###########################################################
nintendo_game_boy_advance = {}
nintendo_game_boy_advance[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_game_boy_advance[keys.platform_key_category] = categories.game_category_nintendo
nintendo_game_boy_advance[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_game_boy_advance
nintendo_game_boy_advance[keys.platform_key_addons] = []
nintendo_game_boy_advance[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_game_boy_advance[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_advance[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_game_boy_advance] = nintendo_game_boy_advance

###########################################################
# Nintendo Game Boy Advance e-Reader
###########################################################
nintendo_game_boy_advance_ereader = {}
nintendo_game_boy_advance_ereader[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_game_boy_advance_ereader[keys.platform_key_category] = categories.game_category_nintendo
nintendo_game_boy_advance_ereader[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_game_boy_advance_ereader
nintendo_game_boy_advance_ereader[keys.platform_key_addons] = []
nintendo_game_boy_advance_ereader[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_game_boy_advance_ereader[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_advance_ereader[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_game_boy_advance_ereader] = nintendo_game_boy_advance_ereader

###########################################################
# Nintendo Game Boy Color
###########################################################
nintendo_game_boy_color = {}
nintendo_game_boy_color[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_game_boy_color[keys.platform_key_category] = categories.game_category_nintendo
nintendo_game_boy_color[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_game_boy_color
nintendo_game_boy_color[keys.platform_key_addons] = []
nintendo_game_boy_color[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_game_boy_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_color[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_game_boy_color] = nintendo_game_boy_color

###########################################################
# Nintendo Gamecube
###########################################################
nintendo_gamecube = {}
nintendo_gamecube[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_gamecube[keys.platform_key_category] = categories.game_category_nintendo
nintendo_gamecube[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_gamecube
nintendo_gamecube[keys.platform_key_addons] = []
nintendo_gamecube[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_gamecube[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_gamecube[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_gamecube] = nintendo_gamecube

###########################################################
# Nintendo NES
###########################################################
nintendo_nes = {}
nintendo_nes[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_nes[keys.platform_key_category] = categories.game_category_nintendo
nintendo_nes[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_nes
nintendo_nes[keys.platform_key_addons] = []
nintendo_nes[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_nes[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_nes[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_nes] = nintendo_nes

###########################################################
# Nintendo SNES
###########################################################
nintendo_snes = {}
nintendo_snes[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_snes[keys.platform_key_category] = categories.game_category_nintendo
nintendo_snes[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_snes
nintendo_snes[keys.platform_key_addons] = []
nintendo_snes[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_snes[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_snes[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_snes] = nintendo_snes

###########################################################
# Nintendo SNES MSU-1
###########################################################
nintendo_snes_msu1 = {}
nintendo_snes_msu1[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_snes_msu1[keys.platform_key_category] = categories.game_category_nintendo
nintendo_snes_msu1[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_snes_msu1
nintendo_snes_msu1[keys.platform_key_addons] = []
nintendo_snes_msu1[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_snes_msu1[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_snes_msu1[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_snes_msu1] = nintendo_snes_msu1

###########################################################
# Nintendo Super Famicom
###########################################################
nintendo_super_famicom = {}
nintendo_super_famicom[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_super_famicom[keys.platform_key_category] = categories.game_category_nintendo
nintendo_super_famicom[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_super_famicom
nintendo_super_famicom[keys.platform_key_addons] = []
nintendo_super_famicom[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_super_famicom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_famicom[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_super_famicom] = nintendo_super_famicom

###########################################################
# Nintendo Super Game Boy
###########################################################
nintendo_super_game_boy = {}
nintendo_super_game_boy[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_super_game_boy[keys.platform_key_category] = categories.game_category_nintendo
nintendo_super_game_boy[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_super_game_boy
nintendo_super_game_boy[keys.platform_key_addons] = []
nintendo_super_game_boy[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_super_game_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_game_boy[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_super_game_boy] = nintendo_super_game_boy

###########################################################
# Nintendo Super Game Boy Color
###########################################################
nintendo_super_game_boy_color = {}
nintendo_super_game_boy_color[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_super_game_boy_color[keys.platform_key_category] = categories.game_category_nintendo
nintendo_super_game_boy_color[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_super_game_boy_color
nintendo_super_game_boy_color[keys.platform_key_addons] = []
nintendo_super_game_boy_color[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_super_game_boy_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_game_boy_color[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_super_game_boy_color] = nintendo_super_game_boy_color

###########################################################
# Nintendo Switch
###########################################################
nintendo_switch = {}
nintendo_switch[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_switch[keys.platform_key_category] = categories.game_category_nintendo
nintendo_switch[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_switch
nintendo_switch[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_switch[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_switch[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_switch[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_switch] = nintendo_switch

###########################################################
# Nintendo Switch eShop
###########################################################
nintendo_switch_eshop = {}
nintendo_switch_eshop[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_switch_eshop[keys.platform_key_category] = categories.game_category_nintendo
nintendo_switch_eshop[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_switch_eshop
nintendo_switch_eshop[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_switch_eshop[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_switch_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_switch_eshop[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_switch_eshop] = nintendo_switch_eshop

###########################################################
# Nintendo Virtual Boy
###########################################################
nintendo_virtual_boy = {}
nintendo_virtual_boy[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_virtual_boy[keys.platform_key_category] = categories.game_category_nintendo
nintendo_virtual_boy[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_virtual_boy
nintendo_virtual_boy[keys.platform_key_addons] = []
nintendo_virtual_boy[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_virtual_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_virtual_boy[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_virtual_boy] = nintendo_virtual_boy

###########################################################
# Nintendo Wii
###########################################################
nintendo_wii = {}
nintendo_wii[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_wii[keys.platform_key_category] = categories.game_category_nintendo
nintendo_wii[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_wii
nintendo_wii[keys.platform_key_addons] = [types.addon_type_dlc]
nintendo_wii[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_wii[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_wii] = nintendo_wii

###########################################################
# Nintendo Wii U
###########################################################
nintendo_wii_u = {}
nintendo_wii_u[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_wii_u[keys.platform_key_category] = categories.game_category_nintendo
nintendo_wii_u[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_wii_u
nintendo_wii_u[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_wii_u[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_wii_u[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii_u[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_wii_u] = nintendo_wii_u

###########################################################
# Nintendo Wii U eShop
###########################################################
nintendo_wii_u_eshop = {}
nintendo_wii_u_eshop[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_wii_u_eshop[keys.platform_key_category] = categories.game_category_nintendo
nintendo_wii_u_eshop[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_wii_u_eshop
nintendo_wii_u_eshop[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_wii_u_eshop[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_wii_u_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii_u_eshop[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_wii_u_eshop] = nintendo_wii_u_eshop


###########################################################
# Nintendo WiiWare
###########################################################
nintendo_wiiware = {}
nintendo_wiiware[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_wiiware[keys.platform_key_category] = categories.game_category_nintendo
nintendo_wiiware[keys.platform_key_subcategory] = categories.game_subcategory_nintendo_wiiware
nintendo_wiiware[keys.platform_key_addons] = [types.addon_type_dlc]
nintendo_wiiware[keys.platform_key_launcher] = [types.launch_type_file]
nintendo_wiiware[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wiiware[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nintendo_wiiware] = nintendo_wiiware

######################################################################################

###########################################################
# Apple iOS
###########################################################
apple_ios = {}
apple_ios[keys.platform_key_supercategory] = categories.game_supercategory_roms
apple_ios[keys.platform_key_category] = categories.game_category_other
apple_ios[keys.platform_key_subcategory] = categories.game_subcategory_apple_ios
apple_ios[keys.platform_key_addons] = []
apple_ios[keys.platform_key_launcher] = [types.launch_type_none]
apple_ios[keys.platform_key_autofill_json] = [keys.json_key_files]
apple_ios[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_apple_ios] = apple_ios

###########################################################
# Apple MacOS 8
###########################################################
apple_macos_8 = {}
apple_macos_8[keys.platform_key_supercategory] = categories.game_supercategory_roms
apple_macos_8[keys.platform_key_category] = categories.game_category_other
apple_macos_8[keys.platform_key_subcategory] = categories.game_subcategory_apple_macos_8
apple_macos_8[keys.platform_key_addons] = []
apple_macos_8[keys.platform_key_launcher] = [types.launch_type_file]
apple_macos_8[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
apple_macos_8[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_apple_macos_8] = apple_macos_8

###########################################################
# Arcade
###########################################################
arcade = {}
arcade[keys.platform_key_supercategory] = categories.game_supercategory_roms
arcade[keys.platform_key_category] = categories.game_category_other
arcade[keys.platform_key_subcategory] = categories.game_subcategory_arcade
arcade[keys.platform_key_addons] = []
arcade[keys.platform_key_launcher] = [types.launch_type_name]
arcade[keys.platform_key_autofill_json] = [keys.json_key_files]
arcade[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
platforms[categories.game_subcategory_arcade] = arcade

###########################################################
# Atari 800
###########################################################
atari_800 = {}
atari_800[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_800[keys.platform_key_category] = categories.game_category_other
atari_800[keys.platform_key_subcategory] = categories.game_subcategory_atari_800
atari_800[keys.platform_key_addons] = []
atari_800[keys.platform_key_launcher] = [types.launch_type_file]
atari_800[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_800[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_atari_800] = atari_800

###########################################################
# Atari 2600
###########################################################
atari_2600 = {}
atari_2600[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_2600[keys.platform_key_category] = categories.game_category_other
atari_2600[keys.platform_key_subcategory] = categories.game_subcategory_atari_2600
atari_2600[keys.platform_key_addons] = []
atari_2600[keys.platform_key_launcher] = [types.launch_type_file]
atari_2600[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_2600[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_atari_2600] = atari_2600

###########################################################
# Atari 5200
###########################################################
atari_5200 = {}
atari_5200[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_5200[keys.platform_key_category] = categories.game_category_other
atari_5200[keys.platform_key_subcategory] = categories.game_subcategory_atari_5200
atari_5200[keys.platform_key_addons] = []
atari_5200[keys.platform_key_launcher] = [types.launch_type_file]
atari_5200[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_5200[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_atari_5200] = atari_5200

###########################################################
# Atari 7800
###########################################################
atari_7800 = {}
atari_7800[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_7800[keys.platform_key_category] = categories.game_category_other
atari_7800[keys.platform_key_subcategory] = categories.game_subcategory_atari_7800
atari_7800[keys.platform_key_addons] = []
atari_7800[keys.platform_key_launcher] = [types.launch_type_file]
atari_7800[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_7800[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_atari_7800] = atari_7800

###########################################################
# Atari Jaguar
###########################################################
atari_jaguar = {}
atari_jaguar[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_jaguar[keys.platform_key_category] = categories.game_category_other
atari_jaguar[keys.platform_key_subcategory] = categories.game_subcategory_atari_jaguar
atari_jaguar[keys.platform_key_addons] = []
atari_jaguar[keys.platform_key_launcher] = [types.launch_type_file]
atari_jaguar[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_jaguar[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_atari_jaguar] = atari_jaguar

###########################################################
# Atari Jaguar CD
###########################################################
atari_jaguar_cd = {}
atari_jaguar_cd[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_jaguar_cd[keys.platform_key_category] = categories.game_category_other
atari_jaguar_cd[keys.platform_key_subcategory] = categories.game_subcategory_atari_jaguar_cd
atari_jaguar_cd[keys.platform_key_addons] = []
atari_jaguar_cd[keys.platform_key_launcher] = [types.launch_type_file]
atari_jaguar_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_jaguar_cd[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_atari_jaguar_cd] = atari_jaguar_cd

###########################################################
# Atari Lynx
###########################################################
atari_lynx = {}
atari_lynx[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_lynx[keys.platform_key_category] = categories.game_category_other
atari_lynx[keys.platform_key_subcategory] = categories.game_subcategory_atari_lynx
atari_lynx[keys.platform_key_addons] = []
atari_lynx[keys.platform_key_launcher] = [types.launch_type_file]
atari_lynx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_lynx[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_atari_lynx] = atari_lynx

###########################################################
# Bandai WonderSwan
###########################################################
bandai_wonderswan = {}
bandai_wonderswan[keys.platform_key_supercategory] = categories.game_supercategory_roms
bandai_wonderswan[keys.platform_key_category] = categories.game_category_other
bandai_wonderswan[keys.platform_key_subcategory] = categories.game_subcategory_bandai_wonderswan
bandai_wonderswan[keys.platform_key_addons] = []
bandai_wonderswan[keys.platform_key_launcher] = [types.launch_type_file]
bandai_wonderswan[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
bandai_wonderswan[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_bandai_wonderswan] = bandai_wonderswan

###########################################################
# Bandai WonderSwan Color
###########################################################
bandai_wonderswan_color = {}
bandai_wonderswan_color[keys.platform_key_supercategory] = categories.game_supercategory_roms
bandai_wonderswan_color[keys.platform_key_category] = categories.game_category_other
bandai_wonderswan_color[keys.platform_key_subcategory] = categories.game_subcategory_bandai_wonderswan_color
bandai_wonderswan_color[keys.platform_key_addons] = []
bandai_wonderswan_color[keys.platform_key_launcher] = [types.launch_type_file]
bandai_wonderswan_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
bandai_wonderswan_color[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_bandai_wonderswan_color] = bandai_wonderswan_color

###########################################################
# Coleco ColecoVision
###########################################################
coleco_colecovision = {}
coleco_colecovision[keys.platform_key_supercategory] = categories.game_supercategory_roms
coleco_colecovision[keys.platform_key_category] = categories.game_category_other
coleco_colecovision[keys.platform_key_subcategory] = categories.game_subcategory_coleco_colecovision
coleco_colecovision[keys.platform_key_addons] = []
coleco_colecovision[keys.platform_key_launcher] = [types.launch_type_file]
coleco_colecovision[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
coleco_colecovision[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_coleco_colecovision] = coleco_colecovision

###########################################################
# Commodore 64
###########################################################
commodore_64 = {}
commodore_64[keys.platform_key_supercategory] = categories.game_supercategory_roms
commodore_64[keys.platform_key_category] = categories.game_category_other
commodore_64[keys.platform_key_subcategory] = categories.game_subcategory_commodore_64
commodore_64[keys.platform_key_addons] = []
commodore_64[keys.platform_key_launcher] = [types.launch_type_file]
commodore_64[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
commodore_64[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_commodore_64] = commodore_64

###########################################################
# Commodore Amiga
###########################################################
commodore_amiga = {}
commodore_amiga[keys.platform_key_supercategory] = categories.game_supercategory_roms
commodore_amiga[keys.platform_key_category] = categories.game_category_other
commodore_amiga[keys.platform_key_subcategory] = categories.game_subcategory_commodore_amiga
commodore_amiga[keys.platform_key_addons] = []
commodore_amiga[keys.platform_key_launcher] = [types.launch_type_file]
commodore_amiga[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
commodore_amiga[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_commodore_amiga] = commodore_amiga

###########################################################
# Google Android
###########################################################
google_android = {}
google_android[keys.platform_key_supercategory] = categories.game_supercategory_roms
google_android[keys.platform_key_category] = categories.game_category_other
google_android[keys.platform_key_subcategory] = categories.game_subcategory_google_android
google_android[keys.platform_key_addons] = []
google_android[keys.platform_key_launcher] = [types.launch_type_none]
google_android[keys.platform_key_autofill_json] = [keys.json_key_files]
google_android[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_google_android] = google_android

###########################################################
# Magnavox Odyssey 2
###########################################################
magnavox_odyssey_2 = {}
magnavox_odyssey_2[keys.platform_key_supercategory] = categories.game_supercategory_roms
magnavox_odyssey_2[keys.platform_key_category] = categories.game_category_other
magnavox_odyssey_2[keys.platform_key_subcategory] = categories.game_subcategory_magnavox_odyssey_2
magnavox_odyssey_2[keys.platform_key_addons] = []
magnavox_odyssey_2[keys.platform_key_launcher] = [types.launch_type_file]
magnavox_odyssey_2[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
magnavox_odyssey_2[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_magnavox_odyssey_2] = magnavox_odyssey_2

###########################################################
# Mattel Intellivision
###########################################################
mattel_intellivision = {}
mattel_intellivision[keys.platform_key_supercategory] = categories.game_supercategory_roms
mattel_intellivision[keys.platform_key_category] = categories.game_category_other
mattel_intellivision[keys.platform_key_subcategory] = categories.game_subcategory_mattel_intellivision
mattel_intellivision[keys.platform_key_addons] = []
mattel_intellivision[keys.platform_key_launcher] = [types.launch_type_file]
mattel_intellivision[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
mattel_intellivision[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_mattel_intellivision] = mattel_intellivision

###########################################################
# NEC PC-Engine
###########################################################
nec_pcengine = {}
nec_pcengine[keys.platform_key_supercategory] = categories.game_supercategory_roms
nec_pcengine[keys.platform_key_category] = categories.game_category_other
nec_pcengine[keys.platform_key_subcategory] = categories.game_subcategory_nec_pcengine
nec_pcengine[keys.platform_key_addons] = []
nec_pcengine[keys.platform_key_launcher] = [types.launch_type_file]
nec_pcengine[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_pcengine[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nec_pcengine] = nec_pcengine

###########################################################
# NEC PC-Engine CD
###########################################################
nec_pcengine_cd = {}
nec_pcengine_cd[keys.platform_key_supercategory] = categories.game_supercategory_roms
nec_pcengine_cd[keys.platform_key_category] = categories.game_category_other
nec_pcengine_cd[keys.platform_key_subcategory] = categories.game_subcategory_nec_pcengine_cd
nec_pcengine_cd[keys.platform_key_addons] = []
nec_pcengine_cd[keys.platform_key_launcher] = [types.launch_type_file]
nec_pcengine_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_pcengine_cd[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nec_pcengine_cd] = nec_pcengine_cd

###########################################################
# NEC SuperGrafx
###########################################################
nec_supergrafx = {}
nec_supergrafx[keys.platform_key_supercategory] = categories.game_supercategory_roms
nec_supergrafx[keys.platform_key_category] = categories.game_category_other
nec_supergrafx[keys.platform_key_subcategory] = categories.game_subcategory_nec_supergrafx
nec_supergrafx[keys.platform_key_addons] = []
nec_supergrafx[keys.platform_key_launcher] = [types.launch_type_file]
nec_supergrafx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_supergrafx[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nec_supergrafx] = nec_supergrafx

###########################################################
# NEC TurboGrafx-16
###########################################################
nec_turbografx_16 = {}
nec_turbografx_16[keys.platform_key_supercategory] = categories.game_supercategory_roms
nec_turbografx_16[keys.platform_key_category] = categories.game_category_other
nec_turbografx_16[keys.platform_key_subcategory] = categories.game_subcategory_nec_turbografx_16
nec_turbografx_16[keys.platform_key_addons] = []
nec_turbografx_16[keys.platform_key_launcher] = [types.launch_type_file]
nec_turbografx_16[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_turbografx_16[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nec_turbografx_16] = nec_turbografx_16

###########################################################
# NEC TurboGrafx CD
###########################################################
nec_turbografx_cd = {}
nec_turbografx_cd[keys.platform_key_supercategory] = categories.game_supercategory_roms
nec_turbografx_cd[keys.platform_key_category] = categories.game_category_other
nec_turbografx_cd[keys.platform_key_subcategory] = categories.game_subcategory_nec_turbografx_cd
nec_turbografx_cd[keys.platform_key_addons] = []
nec_turbografx_cd[keys.platform_key_launcher] = [types.launch_type_file]
nec_turbografx_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_turbografx_cd[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_nec_turbografx_cd] = nec_turbografx_cd

###########################################################
# Nokia N-Gage
###########################################################
nokia_ngage = {}
nokia_ngage[keys.platform_key_supercategory] = categories.game_supercategory_roms
nokia_ngage[keys.platform_key_category] = categories.game_category_other
nokia_ngage[keys.platform_key_subcategory] = categories.game_subcategory_nokia_ngage
nokia_ngage[keys.platform_key_addons] = []
nokia_ngage[keys.platform_key_launcher] = [types.launch_type_name]
nokia_ngage[keys.platform_key_autofill_json] = [keys.json_key_files]
nokia_ngage[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
platforms[categories.game_subcategory_nokia_ngage] = nokia_ngage

###########################################################
# Panasonic 3DO
###########################################################
panasonic_3do = {}
panasonic_3do[keys.platform_key_supercategory] = categories.game_supercategory_roms
panasonic_3do[keys.platform_key_category] = categories.game_category_other
panasonic_3do[keys.platform_key_subcategory] = categories.game_subcategory_panasonic_3do
panasonic_3do[keys.platform_key_addons] = []
panasonic_3do[keys.platform_key_launcher] = [types.launch_type_file]
panasonic_3do[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
panasonic_3do[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_panasonic_3do] = panasonic_3do

###########################################################
# Philips CDi
###########################################################
philips_cdi = {}
philips_cdi[keys.platform_key_supercategory] = categories.game_supercategory_roms
philips_cdi[keys.platform_key_category] = categories.game_category_other
philips_cdi[keys.platform_key_subcategory] = categories.game_subcategory_philips_cdi
philips_cdi[keys.platform_key_addons] = []
philips_cdi[keys.platform_key_launcher] = [types.launch_type_file]
philips_cdi[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
philips_cdi[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_philips_cdi] = philips_cdi

###########################################################
# SNK Neo Geo Pocket Color
###########################################################
snk_neogeo_pocket_color = {}
snk_neogeo_pocket_color[keys.platform_key_supercategory] = categories.game_supercategory_roms
snk_neogeo_pocket_color[keys.platform_key_category] = categories.game_category_other
snk_neogeo_pocket_color[keys.platform_key_subcategory] = categories.game_subcategory_snk_neogeo_pocket_color
snk_neogeo_pocket_color[keys.platform_key_addons] = []
snk_neogeo_pocket_color[keys.platform_key_launcher] = [types.launch_type_file]
snk_neogeo_pocket_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
snk_neogeo_pocket_color[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_snk_neogeo_pocket_color] = snk_neogeo_pocket_color

###########################################################
# Sega 32X
###########################################################
sega_32x = {}
sega_32x[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_32x[keys.platform_key_category] = categories.game_category_other
sega_32x[keys.platform_key_subcategory] = categories.game_subcategory_sega_32x
sega_32x[keys.platform_key_addons] = []
sega_32x[keys.platform_key_launcher] = [types.launch_type_file]
sega_32x[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_32x[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sega_32x] = sega_32x

###########################################################
# Sega CD
###########################################################
sega_cd = {}
sega_cd[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_cd[keys.platform_key_category] = categories.game_category_other
sega_cd[keys.platform_key_subcategory] = categories.game_subcategory_sega_cd
sega_cd[keys.platform_key_addons] = []
sega_cd[keys.platform_key_launcher] = [types.launch_type_file]
sega_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_cd[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sega_cd] = sega_cd

###########################################################
# Sega CD 32X
###########################################################
sega_cd_32x = {}
sega_cd_32x[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_cd_32x[keys.platform_key_category] = categories.game_category_other
sega_cd_32x[keys.platform_key_subcategory] = categories.game_subcategory_sega_cd_32x
sega_cd_32x[keys.platform_key_addons] = []
sega_cd_32x[keys.platform_key_launcher] = [types.launch_type_file]
sega_cd_32x[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_cd_32x[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sega_cd_32x] = sega_cd_32x

###########################################################
# Sega Dreamcast
###########################################################
sega_dreamcast = {}
sega_dreamcast[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_dreamcast[keys.platform_key_category] = categories.game_category_other
sega_dreamcast[keys.platform_key_subcategory] = categories.game_subcategory_sega_dreamcast
sega_dreamcast[keys.platform_key_addons] = []
sega_dreamcast[keys.platform_key_launcher] = [types.launch_type_file]
sega_dreamcast[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_dreamcast[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sega_dreamcast] = sega_dreamcast

###########################################################
# Sega Game Gear
###########################################################
sega_game_gear = {}
sega_game_gear[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_game_gear[keys.platform_key_category] = categories.game_category_other
sega_game_gear[keys.platform_key_subcategory] = categories.game_subcategory_sega_game_gear
sega_game_gear[keys.platform_key_addons] = []
sega_game_gear[keys.platform_key_launcher] = [types.launch_type_file]
sega_game_gear[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_game_gear[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sega_game_gear] = sega_game_gear

###########################################################
# Sega Genesis
###########################################################
sega_genesis = {}
sega_genesis[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_genesis[keys.platform_key_category] = categories.game_category_other
sega_genesis[keys.platform_key_subcategory] = categories.game_subcategory_sega_genesis
sega_genesis[keys.platform_key_addons] = []
sega_genesis[keys.platform_key_launcher] = [types.launch_type_file]
sega_genesis[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_genesis[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sega_genesis] = sega_genesis

###########################################################
# Sega Master System
###########################################################
sega_master_system = {}
sega_master_system[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_master_system[keys.platform_key_category] = categories.game_category_other
sega_master_system[keys.platform_key_subcategory] = categories.game_subcategory_sega_master_system
sega_master_system[keys.platform_key_addons] = []
sega_master_system[keys.platform_key_launcher] = [types.launch_type_file]
sega_master_system[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_master_system[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sega_master_system] = sega_master_system

###########################################################
# Sega Saturn
###########################################################
sega_saturn = {}
sega_saturn[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_saturn[keys.platform_key_category] = categories.game_category_other
sega_saturn[keys.platform_key_subcategory] = categories.game_subcategory_sega_saturn
sega_saturn[keys.platform_key_addons] = []
sega_saturn[keys.platform_key_launcher] = [types.launch_type_file]
sega_saturn[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_saturn[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sega_saturn] = sega_saturn

###########################################################
# Sinclair ZX Spectrum
###########################################################
sinclair_zx_spectrum = {}
sinclair_zx_spectrum[keys.platform_key_supercategory] = categories.game_supercategory_roms
sinclair_zx_spectrum[keys.platform_key_category] = categories.game_category_other
sinclair_zx_spectrum[keys.platform_key_subcategory] = categories.game_subcategory_sinclair_zx_spectrum
sinclair_zx_spectrum[keys.platform_key_addons] = []
sinclair_zx_spectrum[keys.platform_key_launcher] = [types.launch_type_file]
sinclair_zx_spectrum[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sinclair_zx_spectrum[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sinclair_zx_spectrum] = sinclair_zx_spectrum

###########################################################
# Texas Instruments TI-99-4A
###########################################################
texas_instruments_ti994a = {}
texas_instruments_ti994a[keys.platform_key_supercategory] = categories.game_supercategory_roms
texas_instruments_ti994a[keys.platform_key_category] = categories.game_category_other
texas_instruments_ti994a[keys.platform_key_subcategory] = categories.game_subcategory_texas_instruments_ti994a
texas_instruments_ti994a[keys.platform_key_addons] = []
texas_instruments_ti994a[keys.platform_key_launcher] = [types.launch_type_file]
texas_instruments_ti994a[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
texas_instruments_ti994a[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_texas_instruments_ti994a] = texas_instruments_ti994a

###########################################################
# Tiger Game.com
###########################################################
tiger_gamecom = {}
tiger_gamecom[keys.platform_key_supercategory] = categories.game_supercategory_roms
tiger_gamecom[keys.platform_key_category] = categories.game_category_other
tiger_gamecom[keys.platform_key_subcategory] = categories.game_subcategory_tiger_gamecom
tiger_gamecom[keys.platform_key_addons] = []
tiger_gamecom[keys.platform_key_launcher] = [types.launch_type_file]
tiger_gamecom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
tiger_gamecom[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_tiger_gamecom] = tiger_gamecom

######################################################################################

###########################################################
# Sony PlayStation
###########################################################
sony_playstation = {}
sony_playstation[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation[keys.platform_key_category] = categories.game_category_sony
sony_playstation[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation
sony_playstation[keys.platform_key_addons] = []
sony_playstation[keys.platform_key_launcher] = [types.launch_type_file]
sony_playstation[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sony_playstation] = sony_playstation

###########################################################
# Sony PlayStation 2
###########################################################
sony_playstation_2 = {}
sony_playstation_2[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_2[keys.platform_key_category] = categories.game_category_sony
sony_playstation_2[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_2
sony_playstation_2[keys.platform_key_addons] = []
sony_playstation_2[keys.platform_key_launcher] = [types.launch_type_file]
sony_playstation_2[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_2[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sony_playstation_2] = sony_playstation_2

###########################################################
# Sony PlayStation 3
###########################################################
sony_playstation_3 = {}
sony_playstation_3[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_3[keys.platform_key_category] = categories.game_category_sony
sony_playstation_3[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_3
sony_playstation_3[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_3[keys.platform_key_launcher] = [types.launch_type_file]
sony_playstation_3[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_3[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
platforms[categories.game_subcategory_sony_playstation_3] = sony_playstation_3

###########################################################
# Sony PlayStation 4
###########################################################
sony_playstation_4 = {}
sony_playstation_4[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_4[keys.platform_key_category] = categories.game_category_sony
sony_playstation_4[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_4
sony_playstation_4[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_4[keys.platform_key_launcher] = [types.launch_type_none]
sony_playstation_4[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_4[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sony_playstation_4] = sony_playstation_4

###########################################################
# Sony PlayStation Network - PlayStation 3
###########################################################
sony_playstation_network_ps3 = {}
sony_playstation_network_ps3[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_ps3[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_ps3[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_network_ps3
sony_playstation_network_ps3[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_network_ps3[keys.platform_key_launcher] = [types.launch_type_file]
sony_playstation_network_ps3[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_network_ps3[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
platforms[categories.game_subcategory_sony_playstation_network_ps3] = sony_playstation_network_ps3

###########################################################
# Sony PlayStation Network - PlayStation 4
###########################################################
sony_playstation_network_ps4 = {}
sony_playstation_network_ps4[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_ps4[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_ps4[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_network_ps4
sony_playstation_network_ps4[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_network_ps4[keys.platform_key_launcher] = [types.launch_type_none]
sony_playstation_network_ps4[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_network_ps4[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sony_playstation_network_ps4] = sony_playstation_network_ps4

###########################################################
# Sony PlayStation Network - PlayStation Portable
###########################################################
sony_playstation_network_psp = {}
sony_playstation_network_psp[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_psp[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_psp[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_network_psp
sony_playstation_network_psp[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_network_psp[keys.platform_key_launcher] = [types.launch_type_file]
sony_playstation_network_psp[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_network_psp[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sony_playstation_network_psp] = sony_playstation_network_psp

###########################################################
# Sony PlayStation Network - PlayStation Portable Minis
###########################################################
sony_playstation_network_pspm = {}
sony_playstation_network_pspm[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_pspm[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_pspm[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_network_pspm
sony_playstation_network_pspm[keys.platform_key_addons] = []
sony_playstation_network_pspm[keys.platform_key_launcher] = [types.launch_type_file]
sony_playstation_network_pspm[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_network_pspm[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sony_playstation_network_pspm] = sony_playstation_network_pspm

###########################################################
# Sony PlayStation Network - PlayStation Vita
###########################################################
sony_playstation_network_psv = {}
sony_playstation_network_psv[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_psv[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_psv[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_network_psv
sony_playstation_network_psv[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_network_psv[keys.platform_key_launcher] = [types.launch_type_name]
sony_playstation_network_psv[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_network_psv[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
platforms[categories.game_subcategory_sony_playstation_network_psv] = sony_playstation_network_psv

###########################################################
# Sony PlayStation Portable
###########################################################
sony_playstation_portable = {}
sony_playstation_portable[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_portable[keys.platform_key_category] = categories.game_category_sony
sony_playstation_portable[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_portable
sony_playstation_portable[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_portable[keys.platform_key_launcher] = [types.launch_type_file]
sony_playstation_portable[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_portable[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sony_playstation_portable] = sony_playstation_portable

###########################################################
# Sony PlayStation Portable Video
###########################################################
sony_playstation_portable_video = {}
sony_playstation_portable_video[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_portable_video[keys.platform_key_category] = categories.game_category_sony
sony_playstation_portable_video[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_portable_video
sony_playstation_portable_video[keys.platform_key_addons] = []
sony_playstation_portable_video[keys.platform_key_launcher] = [types.launch_type_none]
sony_playstation_portable_video[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_portable_video[keys.platform_key_fillonce_json] = []
platforms[categories.game_subcategory_sony_playstation_portable_video] = sony_playstation_portable_video

###########################################################
# Sony PlayStation Vita
###########################################################
sony_playstation_vita = {}
sony_playstation_vita[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_vita[keys.platform_key_category] = categories.game_category_sony
sony_playstation_vita[keys.platform_key_subcategory] = categories.game_subcategory_sony_playstation_vita
sony_playstation_vita[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_vita[keys.platform_key_launcher] = [types.launch_type_name]
sony_playstation_vita[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_vita[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
platforms[categories.game_subcategory_sony_playstation_vita] = sony_playstation_vita
