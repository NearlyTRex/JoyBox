# Imports
import os
import sys

# Local imports
from . import categories
from . import keys
from . import types

# Platforms
platforms = {}

######################################################################################

###########################################################
# Computer - Amazon Games
###########################################################
computer_amazon_games = {}
computer_amazon_games[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_amazon_games[keys.platform_key_category] = categories.game_category_computer
computer_amazon_games[keys.platform_key_subcategory] = "Amazon Games"
computer_amazon_games[keys.platform_key_transforms] = [types.transform_type_exe_to_raw_plain]
computer_amazon_games[keys.platform_key_addons] = []
computer_amazon_games[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Amazon Games"] = computer_amazon_games

###########################################################
# Computer - Disc
###########################################################
computer_disc = {}
computer_disc[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_disc[keys.platform_key_category] = categories.game_category_computer
computer_disc[keys.platform_key_subcategory] = "Disc"
computer_disc[keys.platform_key_transforms] = [types.transform_type_exe_to_install]
computer_disc[keys.platform_key_addons] = []
computer_disc[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Disc"] = computer_disc

###########################################################
# Computer - Epic Games
###########################################################
computer_epic_games = {}
computer_epic_games[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_epic_games[keys.platform_key_category] = categories.game_category_computer
computer_epic_games[keys.platform_key_subcategory] = "Epic Games"
computer_epic_games[keys.platform_key_transforms] = [types.transform_type_exe_to_raw_plain]
computer_epic_games[keys.platform_key_addons] = []
computer_epic_games[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Epic Games"] = computer_epic_games

###########################################################
# Computer - GOG
###########################################################
computer_gog = {}
computer_gog[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_gog[keys.platform_key_category] = categories.game_category_computer
computer_gog[keys.platform_key_subcategory] = "GOG"
computer_gog[keys.platform_key_transforms] = [types.transform_type_exe_to_install]
computer_gog[keys.platform_key_addons] = []
computer_gog[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - GOG"] = computer_gog

###########################################################
# Computer - Humble Bundle
###########################################################
computer_humble_bundle = {}
computer_humble_bundle[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_humble_bundle[keys.platform_key_category] = categories.game_category_computer
computer_humble_bundle[keys.platform_key_subcategory] = "Humble Bundle"
computer_humble_bundle[keys.platform_key_transforms] = [types.transform_type_exe_to_install]
computer_humble_bundle[keys.platform_key_addons] = []
computer_humble_bundle[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Humble Bundle"] = computer_humble_bundle

###########################################################
# Computer - Itchio
###########################################################
computer_itchio = {}
computer_itchio[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_itchio[keys.platform_key_category] = categories.game_category_computer
computer_itchio[keys.platform_key_subcategory] = "Itchio"
computer_itchio[keys.platform_key_transforms] = [types.transform_type_exe_to_raw_plain]
computer_itchio[keys.platform_key_addons] = []
computer_itchio[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Itchio"] = computer_itchio

###########################################################
# Computer - Puppet Combo
###########################################################
computer_puppet_combo = {}
computer_puppet_combo[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_puppet_combo[keys.platform_key_category] = categories.game_category_computer
computer_puppet_combo[keys.platform_key_subcategory] = "Puppet Combo"
computer_puppet_combo[keys.platform_key_transforms] = [types.transform_type_exe_to_raw_plain]
computer_puppet_combo[keys.platform_key_addons] = []
computer_puppet_combo[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Puppet Combo"] = computer_puppet_combo

###########################################################
# Computer - Red Candle
###########################################################
computer_red_candle = {}
computer_red_candle[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_red_candle[keys.platform_key_category] = categories.game_category_computer
computer_red_candle[keys.platform_key_subcategory] = "Red Candle"
computer_red_candle[keys.platform_key_transforms] = [types.transform_type_exe_to_install]
computer_red_candle[keys.platform_key_addons] = []
computer_red_candle[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Red Candle"] = computer_red_candle

###########################################################
# Computer - Square Enix
###########################################################
computer_square_enix = {}
computer_square_enix[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_square_enix[keys.platform_key_category] = categories.game_category_computer
computer_square_enix[keys.platform_key_subcategory] = "Square Enix"
computer_square_enix[keys.platform_key_transforms] = [types.transform_type_exe_to_install]
computer_square_enix[keys.platform_key_addons] = []
computer_square_enix[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Square Enix"] = computer_square_enix

###########################################################
# Computer - Steam
###########################################################
computer_steam = {}
computer_steam[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_steam[keys.platform_key_category] = categories.game_category_computer
computer_steam[keys.platform_key_subcategory] = "Steam"
computer_steam[keys.platform_key_transforms] = [types.transform_type_exe_to_raw_plain]
computer_steam[keys.platform_key_addons] = []
computer_steam[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Steam"] = computer_steam

###########################################################
# Computer - Zoom
###########################################################
computer_zoom = {}
computer_zoom[keys.platform_key_supercategory] = categories.game_supercategory_roms
computer_zoom[keys.platform_key_category] = categories.game_category_computer
computer_zoom[keys.platform_key_subcategory] = "Zoom"
computer_zoom[keys.platform_key_transforms] = [types.transform_type_exe_to_install]
computer_zoom[keys.platform_key_addons] = []
computer_zoom[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Computer - Zoom"] = computer_zoom

######################################################################################

###########################################################
# Microsoft MSX
###########################################################
microsoft_msx = {}
microsoft_msx[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_msx[keys.platform_key_category] = categories.game_category_microsoft
microsoft_msx[keys.platform_key_subcategory] = "Microsoft MSX"
microsoft_msx[keys.platform_key_transforms] = []
microsoft_msx[keys.platform_key_addons] = []
microsoft_msx[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Microsoft MSX"] = microsoft_msx

###########################################################
# Microsoft Xbox
###########################################################
microsoft_xbox = {}
microsoft_xbox[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox[keys.platform_key_subcategory] = "Microsoft Xbox"
microsoft_xbox[keys.platform_key_transforms] = [types.transform_type_chd_to_iso, types.transform_type_iso_to_xiso]
microsoft_xbox[keys.platform_key_addons] = []
microsoft_xbox[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Microsoft Xbox"] = microsoft_xbox

###########################################################
# Microsoft Xbox 360
###########################################################
microsoft_xbox_360 = {}
microsoft_xbox_360[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_360[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_360[keys.platform_key_subcategory] = "Microsoft Xbox 360"
microsoft_xbox_360[keys.platform_key_transforms] = [types.transform_type_chd_to_iso, types.transform_type_iso_to_xiso]
microsoft_xbox_360[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
microsoft_xbox_360[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Microsoft Xbox 360"] = microsoft_xbox_360

###########################################################
# Microsoft Xbox 360 GOD
###########################################################
microsoft_xbox_360_god = {}
microsoft_xbox_360_god[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_360_god[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_360_god[keys.platform_key_subcategory] = "Microsoft Xbox 360 GOD"
microsoft_xbox_360_god[keys.platform_key_transforms] = []
microsoft_xbox_360_god[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
microsoft_xbox_360_god[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Microsoft Xbox 360 GOD"] = microsoft_xbox_360_god

###########################################################
# Microsoft Xbox 360 XBLA
###########################################################
microsoft_xbox_360_xbla = {}
microsoft_xbox_360_xbla[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_360_xbla[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_360_xbla[keys.platform_key_subcategory] = "Microsoft Xbox 360 XBLA"
microsoft_xbox_360_xbla[keys.platform_key_transforms] = []
microsoft_xbox_360_xbla[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
microsoft_xbox_360_xbla[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Microsoft Xbox 360 XBLA"] = microsoft_xbox_360_xbla

###########################################################
# Microsoft Xbox 360 XIG
###########################################################
microsoft_xbox_360_xig = {}
microsoft_xbox_360_xig[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_360_xig[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_360_xig[keys.platform_key_subcategory] = "Microsoft Xbox 360 XIG"
microsoft_xbox_360_xig[keys.platform_key_transforms] = []
microsoft_xbox_360_xig[keys.platform_key_addons] = []
microsoft_xbox_360_xig[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Microsoft Xbox 360 XIG"] = microsoft_xbox_360_xig

###########################################################
# Microsoft Xbox One
###########################################################
microsoft_xbox_one = {}
microsoft_xbox_one[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_one[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_one[keys.platform_key_subcategory] = "Microsoft Xbox One"
microsoft_xbox_one[keys.platform_key_transforms] = []
microsoft_xbox_one[keys.platform_key_addons] = []
microsoft_xbox_one[keys.platform_key_launcher] = [types.launch_type_none]
platforms["Microsoft Xbox One"] = microsoft_xbox_one

###########################################################
# Microsoft Xbox One GOD
###########################################################
microsoft_xbox_one_god = {}
microsoft_xbox_one_god[keys.platform_key_supercategory] = categories.game_supercategory_roms
microsoft_xbox_one_god[keys.platform_key_category] = categories.game_category_microsoft
microsoft_xbox_one_god[keys.platform_key_subcategory] = "Microsoft Xbox One GOD"
microsoft_xbox_one_god[keys.platform_key_transforms] = []
microsoft_xbox_one_god[keys.platform_key_addons] = []
microsoft_xbox_one_god[keys.platform_key_launcher] = [types.launch_type_none]
platforms["Microsoft Xbox One GOD"] = microsoft_xbox_one_god

######################################################################################

###########################################################
# Nintendo 3DS
###########################################################
nintendo_3ds = {}
nintendo_3ds[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_3ds[keys.platform_key_category] = categories.game_category_nintendo
nintendo_3ds[keys.platform_key_subcategory] = "Nintendo 3DS"
nintendo_3ds[keys.platform_key_transforms] = []
nintendo_3ds[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_3ds[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo 3DS"] = nintendo_3ds

###########################################################
# Nintendo 3DS Apps
###########################################################
nintendo_3ds_apps = {}
nintendo_3ds_apps[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_3ds_apps[keys.platform_key_category] = categories.game_category_nintendo
nintendo_3ds_apps[keys.platform_key_subcategory] = "Nintendo 3DS Apps"
nintendo_3ds_apps[keys.platform_key_transforms] = []
nintendo_3ds_apps[keys.platform_key_addons] = []
nintendo_3ds_apps[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo 3DS Apps"] = nintendo_3ds_apps

###########################################################
# Nintendo 3DS eShop
###########################################################
nintendo_3ds_eshop = {}
nintendo_3ds_eshop[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_3ds_eshop[keys.platform_key_category] = categories.game_category_nintendo
nintendo_3ds_eshop[keys.platform_key_subcategory] = "Nintendo 3DS eShop"
nintendo_3ds_eshop[keys.platform_key_transforms] = []
nintendo_3ds_eshop[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_3ds_eshop[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo 3DS eShop"] = nintendo_3ds_eshop

###########################################################
# Nintendo 64
###########################################################
nintendo_64 = {}
nintendo_64[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_64[keys.platform_key_category] = categories.game_category_nintendo
nintendo_64[keys.platform_key_subcategory] = "Nintendo 64"
nintendo_64[keys.platform_key_transforms] = []
nintendo_64[keys.platform_key_addons] = []
nintendo_64[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo 64"] = nintendo_64

###########################################################
# Nintendo DS
###########################################################
nintendo_ds = {}
nintendo_ds[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_ds[keys.platform_key_category] = categories.game_category_nintendo
nintendo_ds[keys.platform_key_subcategory] = "Nintendo DS"
nintendo_ds[keys.platform_key_transforms] = []
nintendo_ds[keys.platform_key_addons] = []
nintendo_ds[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo DS"] = nintendo_ds

###########################################################
# Nintendo DSi
###########################################################
nintendo_dsi = {}
nintendo_dsi[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_dsi[keys.platform_key_category] = categories.game_category_nintendo
nintendo_dsi[keys.platform_key_subcategory] = "Nintendo DSi"
nintendo_dsi[keys.platform_key_transforms] = []
nintendo_dsi[keys.platform_key_addons] = []
nintendo_dsi[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo DSi"] = nintendo_dsi

###########################################################
# Nintendo Famicom
###########################################################
nintendo_famicom = {}
nintendo_famicom[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_famicom[keys.platform_key_category] = categories.game_category_nintendo
nintendo_famicom[keys.platform_key_subcategory] = "Nintendo Famicom"
nintendo_famicom[keys.platform_key_transforms] = []
nintendo_famicom[keys.platform_key_addons] = []
nintendo_famicom[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Famicom"] = nintendo_famicom

###########################################################
# Nintendo Game Boy
###########################################################
nintendo_game_boy = {}
nintendo_game_boy[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_game_boy[keys.platform_key_category] = categories.game_category_nintendo
nintendo_game_boy[keys.platform_key_subcategory] = "Nintendo Game Boy"
nintendo_game_boy[keys.platform_key_transforms] = []
nintendo_game_boy[keys.platform_key_addons] = []
nintendo_game_boy[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Game Boy"] = nintendo_game_boy

###########################################################
# Nintendo Game Boy Advance
###########################################################
nintendo_game_boy_advance = {}
nintendo_game_boy_advance[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_game_boy_advance[keys.platform_key_category] = categories.game_category_nintendo
nintendo_game_boy_advance[keys.platform_key_subcategory] = "Nintendo Game Boy Advance"
nintendo_game_boy_advance[keys.platform_key_transforms] = []
nintendo_game_boy_advance[keys.platform_key_addons] = []
nintendo_game_boy_advance[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Game Boy Advance"] = nintendo_game_boy_advance

###########################################################
# Nintendo Game Boy Advance e-Reader
###########################################################
nintendo_game_boy_advance_ereader = {}
nintendo_game_boy_advance_ereader[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_game_boy_advance_ereader[keys.platform_key_category] = categories.game_category_nintendo
nintendo_game_boy_advance_ereader[keys.platform_key_subcategory] = "Nintendo Game Boy Advance e-Reader"
nintendo_game_boy_advance_ereader[keys.platform_key_transforms] = []
nintendo_game_boy_advance_ereader[keys.platform_key_addons] = []
nintendo_game_boy_advance_ereader[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Game Boy Advance e-Reader"] = nintendo_game_boy_advance_ereader

###########################################################
# Nintendo Game Boy Color
###########################################################
nintendo_game_boy_color = {}
nintendo_game_boy_color[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_game_boy_color[keys.platform_key_category] = categories.game_category_nintendo
nintendo_game_boy_color[keys.platform_key_subcategory] = "Nintendo Game Boy Color"
nintendo_game_boy_color[keys.platform_key_transforms] = []
nintendo_game_boy_color[keys.platform_key_addons] = []
nintendo_game_boy_color[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Game Boy Color"] = nintendo_game_boy_color

###########################################################
# Nintendo Gamecube
###########################################################
nintendo_gamecube = {}
nintendo_gamecube[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_gamecube[keys.platform_key_category] = categories.game_category_nintendo
nintendo_gamecube[keys.platform_key_subcategory] = "Nintendo Gamecube"
nintendo_gamecube[keys.platform_key_transforms] = []
nintendo_gamecube[keys.platform_key_addons] = []
nintendo_gamecube[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Gamecube"] = nintendo_gamecube

###########################################################
# Nintendo NES
###########################################################
nintendo_nes = {}
nintendo_nes[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_nes[keys.platform_key_category] = categories.game_category_nintendo
nintendo_nes[keys.platform_key_subcategory] = "Nintendo NES"
nintendo_nes[keys.platform_key_transforms] = []
nintendo_nes[keys.platform_key_addons] = []
nintendo_nes[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo NES"] = nintendo_nes

###########################################################
# Nintendo SNES
###########################################################
nintendo_snes = {}
nintendo_snes[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_snes[keys.platform_key_category] = categories.game_category_nintendo
nintendo_snes[keys.platform_key_subcategory] = "Nintendo SNES"
nintendo_snes[keys.platform_key_transforms] = []
nintendo_snes[keys.platform_key_addons] = []
nintendo_snes[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo SNES"] = nintendo_snes

###########################################################
# Nintendo Super Famicom
###########################################################
nintendo_super_famicom = {}
nintendo_super_famicom[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_super_famicom[keys.platform_key_category] = categories.game_category_nintendo
nintendo_super_famicom[keys.platform_key_subcategory] = "Nintendo Super Famicom"
nintendo_super_famicom[keys.platform_key_transforms] = []
nintendo_super_famicom[keys.platform_key_addons] = []
nintendo_super_famicom[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Super Famicom"] = nintendo_super_famicom

###########################################################
# Nintendo Super Game Boy
###########################################################
nintendo_super_game_boy = {}
nintendo_super_game_boy[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_super_game_boy[keys.platform_key_category] = categories.game_category_nintendo
nintendo_super_game_boy[keys.platform_key_subcategory] = "Nintendo Super Game Boy"
nintendo_super_game_boy[keys.platform_key_transforms] = []
nintendo_super_game_boy[keys.platform_key_addons] = []
nintendo_super_game_boy[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Super Game Boy"] = nintendo_super_game_boy

###########################################################
# Nintendo Super Game Boy Color
###########################################################
nintendo_super_game_boy_color = {}
nintendo_super_game_boy_color[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_super_game_boy_color[keys.platform_key_category] = categories.game_category_nintendo
nintendo_super_game_boy_color[keys.platform_key_subcategory] = "Nintendo Super Game Boy Color"
nintendo_super_game_boy_color[keys.platform_key_transforms] = []
nintendo_super_game_boy_color[keys.platform_key_addons] = []
nintendo_super_game_boy_color[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Super Game Boy Color"] = nintendo_super_game_boy_color

###########################################################
# Nintendo Switch
###########################################################
nintendo_switch = {}
nintendo_switch[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_switch[keys.platform_key_category] = categories.game_category_nintendo
nintendo_switch[keys.platform_key_subcategory] = "Nintendo Switch"
nintendo_switch[keys.platform_key_transforms] = []
nintendo_switch[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_switch[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Switch"] = nintendo_switch

###########################################################
# Nintendo Switch eShop
###########################################################
nintendo_switch_eshop = {}
nintendo_switch_eshop[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_switch_eshop[keys.platform_key_category] = categories.game_category_nintendo
nintendo_switch_eshop[keys.platform_key_subcategory] = "Nintendo Switch eShop"
nintendo_switch_eshop[keys.platform_key_transforms] = []
nintendo_switch_eshop[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_switch_eshop[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Switch eShop"] = nintendo_switch_eshop

###########################################################
# Nintendo Virtual Boy
###########################################################
nintendo_virtual_boy = {}
nintendo_virtual_boy[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_virtual_boy[keys.platform_key_category] = categories.game_category_nintendo
nintendo_virtual_boy[keys.platform_key_subcategory] = "Nintendo Virtual Boy"
nintendo_virtual_boy[keys.platform_key_transforms] = []
nintendo_virtual_boy[keys.platform_key_addons] = []
nintendo_virtual_boy[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Virtual Boy"] = nintendo_virtual_boy

###########################################################
# Nintendo Wii
###########################################################
nintendo_wii = {}
nintendo_wii[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_wii[keys.platform_key_category] = categories.game_category_nintendo
nintendo_wii[keys.platform_key_subcategory] = "Nintendo Wii"
nintendo_wii[keys.platform_key_transforms] = []
nintendo_wii[keys.platform_key_addons] = [types.addon_type_dlc]
nintendo_wii[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Wii"] = nintendo_wii

###########################################################
# Nintendo Wii U
###########################################################
nintendo_wii_u = {}
nintendo_wii_u[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_wii_u[keys.platform_key_category] = categories.game_category_nintendo
nintendo_wii_u[keys.platform_key_subcategory] = "Nintendo Wii U"
nintendo_wii_u[keys.platform_key_transforms] = []
nintendo_wii_u[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_wii_u[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Wii U"] = nintendo_wii_u

###########################################################
# Nintendo Wii U eShop
###########################################################
nintendo_wii_u_eshop = {}
nintendo_wii_u_eshop[keys.platform_key_supercategory] = categories.game_supercategory_roms
nintendo_wii_u_eshop[keys.platform_key_category] = categories.game_category_nintendo
nintendo_wii_u_eshop[keys.platform_key_subcategory] = "Nintendo Wii U eShop"
nintendo_wii_u_eshop[keys.platform_key_transforms] = []
nintendo_wii_u_eshop[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
nintendo_wii_u_eshop[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Nintendo Wii U eShop"] = nintendo_wii_u_eshop

######################################################################################

###########################################################
# Apple iOS
###########################################################
apple_ios = {}
apple_ios[keys.platform_key_supercategory] = categories.game_supercategory_roms
apple_ios[keys.platform_key_category] = categories.game_category_other
apple_ios[keys.platform_key_subcategory] = "Apple iOS"
apple_ios[keys.platform_key_transforms] = []
apple_ios[keys.platform_key_addons] = []
apple_ios[keys.platform_key_launcher] = [types.launch_type_none]
platforms["Apple iOS"] = apple_ios

###########################################################
# Apple MacOS 8
###########################################################
apple_macos_8 = {}
apple_macos_8[keys.platform_key_supercategory] = categories.game_supercategory_roms
apple_macos_8[keys.platform_key_category] = categories.game_category_other
apple_macos_8[keys.platform_key_subcategory] = "Apple MacOS 8"
apple_macos_8[keys.platform_key_transforms] = []
apple_macos_8[keys.platform_key_addons] = []
apple_macos_8[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Apple MacOS 8"] = apple_macos_8

###########################################################
# Arcade
###########################################################
arcade = {}
arcade[keys.platform_key_supercategory] = categories.game_supercategory_roms
arcade[keys.platform_key_category] = categories.game_category_other
arcade[keys.platform_key_subcategory] = "Arcade"
arcade[keys.platform_key_transforms] = []
arcade[keys.platform_key_addons] = []
arcade[keys.platform_key_launcher] = [types.launch_type_name]
platforms["Arcade"] = arcade

###########################################################
# Atari 800
###########################################################
atari_800 = {}
atari_800[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_800[keys.platform_key_category] = categories.game_category_other
atari_800[keys.platform_key_subcategory] = "Atari 800"
atari_800[keys.platform_key_transforms] = []
atari_800[keys.platform_key_addons] = []
atari_800[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Atari 800"] = atari_800

###########################################################
# Atari 2600
###########################################################
atari_2600 = {}
atari_2600[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_2600[keys.platform_key_category] = categories.game_category_other
atari_2600[keys.platform_key_subcategory] = "Atari 2600"
atari_2600[keys.platform_key_transforms] = []
atari_2600[keys.platform_key_addons] = []
atari_2600[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Atari 2600"] = atari_2600

###########################################################
# Atari 5200
###########################################################
atari_5200 = {}
atari_5200[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_5200[keys.platform_key_category] = categories.game_category_other
atari_5200[keys.platform_key_subcategory] = "Atari 5200"
atari_5200[keys.platform_key_transforms] = []
atari_5200[keys.platform_key_addons] = []
atari_5200[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Atari 5200"] = atari_5200

###########################################################
# Atari 7800
###########################################################
atari_7800 = {}
atari_7800[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_7800[keys.platform_key_category] = categories.game_category_other
atari_7800[keys.platform_key_subcategory] = "Atari 7800"
atari_7800[keys.platform_key_transforms] = []
atari_7800[keys.platform_key_addons] = []
atari_7800[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Atari 7800"] = atari_7800

###########################################################
# Atari Jaguar
###########################################################
atari_jaguar = {}
atari_jaguar[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_jaguar[keys.platform_key_category] = categories.game_category_other
atari_jaguar[keys.platform_key_subcategory] = "Atari Jaguar"
atari_jaguar[keys.platform_key_transforms] = []
atari_jaguar[keys.platform_key_addons] = []
atari_jaguar[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Atari Jaguar"] = atari_jaguar

###########################################################
# Atari Jaguar CD
###########################################################
atari_jaguar_cd = {}
atari_jaguar_cd[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_jaguar_cd[keys.platform_key_category] = categories.game_category_other
atari_jaguar_cd[keys.platform_key_subcategory] = "Atari Jaguar CD"
atari_jaguar_cd[keys.platform_key_transforms] = []
atari_jaguar_cd[keys.platform_key_addons] = []
atari_jaguar_cd[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Atari Jaguar CD"] = atari_jaguar_cd

###########################################################
# Atari Lynx
###########################################################
atari_lynx = {}
atari_lynx[keys.platform_key_supercategory] = categories.game_supercategory_roms
atari_lynx[keys.platform_key_category] = categories.game_category_other
atari_lynx[keys.platform_key_subcategory] = "Atari Lynx"
atari_lynx[keys.platform_key_transforms] = []
atari_lynx[keys.platform_key_addons] = []
atari_lynx[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Atari Lynx"] = atari_lynx

###########################################################
# Bandai WonderSwan
###########################################################
bandai_wonderswan = {}
bandai_wonderswan[keys.platform_key_supercategory] = categories.game_supercategory_roms
bandai_wonderswan[keys.platform_key_category] = categories.game_category_other
bandai_wonderswan[keys.platform_key_subcategory] = "Bandai WonderSwan"
bandai_wonderswan[keys.platform_key_transforms] = []
bandai_wonderswan[keys.platform_key_addons] = []
bandai_wonderswan[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Bandai WonderSwan"] = bandai_wonderswan

###########################################################
# Bandai WonderSwan Color
###########################################################
bandai_wonderswan_color = {}
bandai_wonderswan_color[keys.platform_key_supercategory] = categories.game_supercategory_roms
bandai_wonderswan_color[keys.platform_key_category] = categories.game_category_other
bandai_wonderswan_color[keys.platform_key_subcategory] = "Bandai WonderSwan Color"
bandai_wonderswan_color[keys.platform_key_transforms] = []
bandai_wonderswan_color[keys.platform_key_addons] = []
bandai_wonderswan_color[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Bandai WonderSwan Color"] = bandai_wonderswan_color

###########################################################
# Coleco ColecoVision
###########################################################
coleco_colecovision = {}
coleco_colecovision[keys.platform_key_supercategory] = categories.game_supercategory_roms
coleco_colecovision[keys.platform_key_category] = categories.game_category_other
coleco_colecovision[keys.platform_key_subcategory] = "Coleco ColecoVision"
coleco_colecovision[keys.platform_key_transforms] = []
coleco_colecovision[keys.platform_key_addons] = []
coleco_colecovision[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Coleco ColecoVision"] = coleco_colecovision

###########################################################
# Commodore 64
###########################################################
commodore_64 = {}
commodore_64[keys.platform_key_supercategory] = categories.game_supercategory_roms
commodore_64[keys.platform_key_category] = categories.game_category_other
commodore_64[keys.platform_key_subcategory] = "Commodore 64"
commodore_64[keys.platform_key_transforms] = []
commodore_64[keys.platform_key_addons] = []
commodore_64[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Commodore 64"] = commodore_64

###########################################################
# Commodore Amiga
###########################################################
commodore_amiga = {}
commodore_amiga[keys.platform_key_supercategory] = categories.game_supercategory_roms
commodore_amiga[keys.platform_key_category] = categories.game_category_other
commodore_amiga[keys.platform_key_subcategory] = "Commodore Amiga"
commodore_amiga[keys.platform_key_transforms] = []
commodore_amiga[keys.platform_key_addons] = []
commodore_amiga[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Commodore Amiga"] = commodore_amiga

###########################################################
# Google Android
###########################################################
google_android = {}
google_android[keys.platform_key_supercategory] = categories.game_supercategory_roms
google_android[keys.platform_key_category] = categories.game_category_other
google_android[keys.platform_key_subcategory] = "Google Android"
google_android[keys.platform_key_transforms] = []
google_android[keys.platform_key_addons] = []
google_android[keys.platform_key_launcher] = [types.launch_type_none]
platforms["Google Android"] = google_android

###########################################################
# Magnavox Odyssey 2
###########################################################
magnavox_odyssey_2 = {}
magnavox_odyssey_2[keys.platform_key_supercategory] = categories.game_supercategory_roms
magnavox_odyssey_2[keys.platform_key_category] = categories.game_category_other
magnavox_odyssey_2[keys.platform_key_subcategory] = "Magnavox Odyssey 2"
magnavox_odyssey_2[keys.platform_key_transforms] = []
magnavox_odyssey_2[keys.platform_key_addons] = []
magnavox_odyssey_2[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Magnavox Odyssey 2"] = magnavox_odyssey_2

###########################################################
# Mattel Intellivision
###########################################################
mattel_intellivision = {}
mattel_intellivision[keys.platform_key_supercategory] = categories.game_supercategory_roms
mattel_intellivision[keys.platform_key_category] = categories.game_category_other
mattel_intellivision[keys.platform_key_subcategory] = "Mattel Intellivision"
mattel_intellivision[keys.platform_key_transforms] = []
mattel_intellivision[keys.platform_key_addons] = []
mattel_intellivision[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Mattel Intellivision"] = mattel_intellivision

###########################################################
# NEC SuperGrafx
###########################################################
nec_supergrafx = {}
nec_supergrafx[keys.platform_key_supercategory] = categories.game_supercategory_roms
nec_supergrafx[keys.platform_key_category] = categories.game_category_other
nec_supergrafx[keys.platform_key_subcategory] = "NEC SuperGrafx"
nec_supergrafx[keys.platform_key_transforms] = []
nec_supergrafx[keys.platform_key_addons] = []
nec_supergrafx[keys.platform_key_launcher] = [types.launch_type_file]
platforms["NEC SuperGrafx"] = nec_supergrafx

###########################################################
# NEC TurboGrafx CD & PC-Engine CD
###########################################################
nec_turbografx_pcengine_cd = {}
nec_turbografx_pcengine_cd[keys.platform_key_supercategory] = categories.game_supercategory_roms
nec_turbografx_pcengine_cd[keys.platform_key_category] = categories.game_category_other
nec_turbografx_pcengine_cd[keys.platform_key_subcategory] = "NEC TurboGrafx CD & PC-Engine CD"
nec_turbografx_pcengine_cd[keys.platform_key_transforms] = []
nec_turbografx_pcengine_cd[keys.platform_key_addons] = []
nec_turbografx_pcengine_cd[keys.platform_key_launcher] = [types.launch_type_file]
platforms["NEC TurboGrafx CD & PC-Engine CD"] = nec_turbografx_pcengine_cd

###########################################################
# NEC TurboGrafx-16 & PC-Engine
###########################################################
nec_turbografx_pcengine = {}
nec_turbografx_pcengine[keys.platform_key_supercategory] = categories.game_supercategory_roms
nec_turbografx_pcengine[keys.platform_key_category] = categories.game_category_other
nec_turbografx_pcengine[keys.platform_key_subcategory] = "NEC TurboGrafx-16 & PC-Engine"
nec_turbografx_pcengine[keys.platform_key_transforms] = []
nec_turbografx_pcengine[keys.platform_key_addons] = []
nec_turbografx_pcengine[keys.platform_key_launcher] = [types.launch_type_file]
platforms["NEC TurboGrafx-16 & PC-Engine"] = nec_turbografx_pcengine

###########################################################
# Nokia N-Gage
###########################################################
nokia_ngage = {}
nokia_ngage[keys.platform_key_supercategory] = categories.game_supercategory_roms
nokia_ngage[keys.platform_key_category] = categories.game_category_other
nokia_ngage[keys.platform_key_subcategory] = "Nokia N-Gage"
nokia_ngage[keys.platform_key_transforms] = []
nokia_ngage[keys.platform_key_addons] = []
nokia_ngage[keys.platform_key_launcher] = [types.launch_type_name]
platforms["Nokia N-Gage"] = nokia_ngage

###########################################################
# Panasonic 3DO
###########################################################
panasonic_3do = {}
panasonic_3do[keys.platform_key_supercategory] = categories.game_supercategory_roms
panasonic_3do[keys.platform_key_category] = categories.game_category_other
panasonic_3do[keys.platform_key_subcategory] = "Panasonic 3DO"
panasonic_3do[keys.platform_key_transforms] = []
panasonic_3do[keys.platform_key_addons] = []
panasonic_3do[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Panasonic 3DO"] = panasonic_3do

###########################################################
# Philips CDi
###########################################################
philips_cdi = {}
philips_cdi[keys.platform_key_supercategory] = categories.game_supercategory_roms
philips_cdi[keys.platform_key_category] = categories.game_category_other
philips_cdi[keys.platform_key_subcategory] = "Philips CDi"
philips_cdi[keys.platform_key_transforms] = []
philips_cdi[keys.platform_key_addons] = []
philips_cdi[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Philips CDi"] = philips_cdi

###########################################################
# SNK Neo Geo Pocket Color
###########################################################
snk_neogeo_pocket_color = {}
snk_neogeo_pocket_color[keys.platform_key_supercategory] = categories.game_supercategory_roms
snk_neogeo_pocket_color[keys.platform_key_category] = categories.game_category_other
snk_neogeo_pocket_color[keys.platform_key_subcategory] = "SNK Neo Geo Pocket Color"
snk_neogeo_pocket_color[keys.platform_key_transforms] = []
snk_neogeo_pocket_color[keys.platform_key_addons] = []
snk_neogeo_pocket_color[keys.platform_key_launcher] = [types.launch_type_file]
platforms["SNK Neo Geo Pocket Color"] = snk_neogeo_pocket_color

###########################################################
# Sega 32X
###########################################################
sega_32x = {}
sega_32x[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_32x[keys.platform_key_category] = categories.game_category_other
sega_32x[keys.platform_key_subcategory] = "Sega 32X"
sega_32x[keys.platform_key_transforms] = []
sega_32x[keys.platform_key_addons] = []
sega_32x[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sega 32X"] = sega_32x

###########################################################
# Sega CD
###########################################################
sega_cd = {}
sega_cd[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_cd[keys.platform_key_category] = categories.game_category_other
sega_cd[keys.platform_key_subcategory] = "Sega CD"
sega_cd[keys.platform_key_transforms] = []
sega_cd[keys.platform_key_addons] = []
sega_cd[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sega CD"] = sega_cd

###########################################################
# Sega CD 32X
###########################################################
sega_cd_32x = {}
sega_cd_32x[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_cd_32x[keys.platform_key_category] = categories.game_category_other
sega_cd_32x[keys.platform_key_subcategory] = "Sega CD 32X"
sega_cd_32x[keys.platform_key_transforms] = []
sega_cd_32x[keys.platform_key_addons] = []
sega_cd_32x[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sega CD 32X"] = sega_cd_32x

###########################################################
# Sega Dreamcast
###########################################################
sega_dreamcast = {}
sega_dreamcast[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_dreamcast[keys.platform_key_category] = categories.game_category_other
sega_dreamcast[keys.platform_key_subcategory] = "Sega Dreamcast"
sega_dreamcast[keys.platform_key_transforms] = []
sega_dreamcast[keys.platform_key_addons] = []
sega_dreamcast[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sega Dreamcast"] = sega_dreamcast

###########################################################
# Sega Game Gear
###########################################################
sega_game_gear = {}
sega_game_gear[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_game_gear[keys.platform_key_category] = categories.game_category_other
sega_game_gear[keys.platform_key_subcategory] = "Sega Game Gear"
sega_game_gear[keys.platform_key_transforms] = []
sega_game_gear[keys.platform_key_addons] = []
sega_game_gear[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sega Game Gear"] = sega_game_gear

###########################################################
# Sega Genesis
###########################################################
sega_genesis = {}
sega_genesis[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_genesis[keys.platform_key_category] = categories.game_category_other
sega_genesis[keys.platform_key_subcategory] = "Sega Genesis"
sega_genesis[keys.platform_key_transforms] = []
sega_genesis[keys.platform_key_addons] = []
sega_genesis[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sega Genesis"] = sega_genesis

###########################################################
# Sega Master System
###########################################################
sega_master_system = {}
sega_master_system[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_master_system[keys.platform_key_category] = categories.game_category_other
sega_master_system[keys.platform_key_subcategory] = "Sega Master System"
sega_master_system[keys.platform_key_transforms] = []
sega_master_system[keys.platform_key_addons] = []
sega_master_system[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sega Master System"] = sega_master_system

###########################################################
# Sega Saturn
###########################################################
sega_saturn = {}
sega_saturn[keys.platform_key_supercategory] = categories.game_supercategory_roms
sega_saturn[keys.platform_key_category] = categories.game_category_other
sega_saturn[keys.platform_key_subcategory] = "Sega Saturn"
sega_saturn[keys.platform_key_transforms] = []
sega_saturn[keys.platform_key_addons] = []
sega_saturn[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sega Saturn"] = sega_saturn

###########################################################
# Sinclair ZX Spectrum
###########################################################
sinclair_zx_spectrum = {}
sinclair_zx_spectrum[keys.platform_key_supercategory] = categories.game_supercategory_roms
sinclair_zx_spectrum[keys.platform_key_category] = categories.game_category_other
sinclair_zx_spectrum[keys.platform_key_subcategory] = "Sinclair ZX Spectrum"
sinclair_zx_spectrum[keys.platform_key_transforms] = []
sinclair_zx_spectrum[keys.platform_key_addons] = []
sinclair_zx_spectrum[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sinclair ZX Spectrum"] = sinclair_zx_spectrum

###########################################################
# Texas Instruments TI-99-4A
###########################################################
texas_instruments_ti994a = {}
texas_instruments_ti994a[keys.platform_key_supercategory] = categories.game_supercategory_roms
texas_instruments_ti994a[keys.platform_key_category] = categories.game_category_other
texas_instruments_ti994a[keys.platform_key_subcategory] = "Texas Instruments TI-99-4A"
texas_instruments_ti994a[keys.platform_key_transforms] = []
texas_instruments_ti994a[keys.platform_key_addons] = []
texas_instruments_ti994a[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Texas Instruments TI-99-4A"] = texas_instruments_ti994a

###########################################################
# Tiger Game.com
###########################################################
tiger_gamecom = {}
tiger_gamecom[keys.platform_key_supercategory] = categories.game_supercategory_roms
tiger_gamecom[keys.platform_key_category] = categories.game_category_other
tiger_gamecom[keys.platform_key_subcategory] = "Tiger Game.com"
tiger_gamecom[keys.platform_key_transforms] = []
tiger_gamecom[keys.platform_key_addons] = []
tiger_gamecom[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Tiger Game.com"] = tiger_gamecom

######################################################################################

###########################################################
# Sony PlayStation
###########################################################
sony_playstation = {}
sony_playstation[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation[keys.platform_key_category] = categories.game_category_sony
sony_playstation[keys.platform_key_subcategory] = "Sony PlayStation"
sony_playstation[keys.platform_key_transforms] = []
sony_playstation[keys.platform_key_addons] = []
sony_playstation[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sony PlayStation"] = sony_playstation

###########################################################
# Sony PlayStation 2
###########################################################
sony_playstation_2 = {}
sony_playstation_2[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_2[keys.platform_key_category] = categories.game_category_sony
sony_playstation_2[keys.platform_key_subcategory] = "Sony PlayStation 2"
sony_playstation_2[keys.platform_key_transforms] = []
sony_playstation_2[keys.platform_key_addons] = []
sony_playstation_2[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sony PlayStation 2"] = sony_playstation_2

###########################################################
# Sony PlayStation 3
###########################################################
sony_playstation_3 = {}
sony_playstation_3[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_3[keys.platform_key_category] = categories.game_category_sony
sony_playstation_3[keys.platform_key_subcategory] = "Sony PlayStation 3"
sony_playstation_3[keys.platform_key_transforms] = [types.transform_type_chd_to_iso, types.transform_type_iso_to_raw_ps3]
sony_playstation_3[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_3[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sony PlayStation 3"] = sony_playstation_3

###########################################################
# Sony PlayStation 4
###########################################################
sony_playstation_4 = {}
sony_playstation_4[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_4[keys.platform_key_category] = categories.game_category_sony
sony_playstation_4[keys.platform_key_subcategory] = "Sony PlayStation 4"
sony_playstation_4[keys.platform_key_transforms] = []
sony_playstation_4[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_4[keys.platform_key_launcher] = [types.launch_type_none]
platforms["Sony PlayStation 4"] = sony_playstation_4

###########################################################
# Sony PlayStation Network - PlayStation 3
###########################################################
sony_playstation_network_ps3 = {}
sony_playstation_network_ps3[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_ps3[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_ps3[keys.platform_key_subcategory] = "Sony PlayStation Network - PlayStation 3"
sony_playstation_network_ps3[keys.platform_key_transforms] = [types.transform_type_pkg_to_raw_ps3]
sony_playstation_network_ps3[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_network_ps3[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sony PlayStation Network - PlayStation 3"] = sony_playstation_network_ps3

###########################################################
# Sony PlayStation Network - PlayStation 4
###########################################################
sony_playstation_network_ps4 = {}
sony_playstation_network_ps4[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_ps4[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_ps4[keys.platform_key_subcategory] = "Sony PlayStation Network - PlayStation 4"
sony_playstation_network_ps4[keys.platform_key_transforms] = []
sony_playstation_network_ps4[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_network_ps4[keys.platform_key_launcher] = [types.launch_type_none]
platforms["Sony PlayStation Network - PlayStation 4"] = sony_playstation_network_ps4

###########################################################
# Sony PlayStation Network - PlayStation Portable
###########################################################
sony_playstation_network_psp = {}
sony_playstation_network_psp[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_psp[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_psp[keys.platform_key_subcategory] = "Sony PlayStation Network - PlayStation Portable"
sony_playstation_network_psp[keys.platform_key_transforms] = []
sony_playstation_network_psp[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_network_psp[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sony PlayStation Network - PlayStation Portable"] = sony_playstation_network_psp

###########################################################
# Sony PlayStation Network - PlayStation Portable Minis
###########################################################
sony_playstation_network_pspm = {}
sony_playstation_network_pspm[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_pspm[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_pspm[keys.platform_key_subcategory] = "Sony PlayStation Network - PlayStation Portable Minis"
sony_playstation_network_pspm[keys.platform_key_transforms] = []
sony_playstation_network_pspm[keys.platform_key_addons] = []
sony_playstation_network_pspm[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sony PlayStation Network - PlayStation Portable Minis"] = sony_playstation_network_pspm

###########################################################
# Sony PlayStation Network - PlayStation Vita
###########################################################
sony_playstation_network_psv = {}
sony_playstation_network_psv[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_network_psv[keys.platform_key_category] = categories.game_category_sony
sony_playstation_network_psv[keys.platform_key_subcategory] = "Sony PlayStation Network - PlayStation Vita"
sony_playstation_network_psv[keys.platform_key_transforms] = [types.transform_type_pkg_to_raw_psv]
sony_playstation_network_psv[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_network_psv[keys.platform_key_launcher] = [types.launch_type_name]
platforms["Sony PlayStation Network - PlayStation Vita"] = sony_playstation_network_psv

###########################################################
# Sony PlayStation Portable
###########################################################
sony_playstation_portable = {}
sony_playstation_portable[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_portable[keys.platform_key_category] = categories.game_category_sony
sony_playstation_portable[keys.platform_key_subcategory] = "Sony PlayStation Portable"
sony_playstation_portable[keys.platform_key_transforms] = []
sony_playstation_portable[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_portable[keys.platform_key_launcher] = [types.launch_type_file]
platforms["Sony PlayStation Portable"] = sony_playstation_portable

###########################################################
# Sony PlayStation Portable Video
###########################################################
sony_playstation_portable_video = {}
sony_playstation_portable_video[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_portable_video[keys.platform_key_category] = categories.game_category_sony
sony_playstation_portable_video[keys.platform_key_subcategory] = "Sony PlayStation Portable Video"
sony_playstation_portable_video[keys.platform_key_transforms] = []
sony_playstation_portable_video[keys.platform_key_addons] = []
sony_playstation_portable_video[keys.platform_key_launcher] = [types.launch_type_none]
platforms["Sony PlayStation Portable Video"] = sony_playstation_portable_video

###########################################################
# Sony PlayStation Vita
###########################################################
sony_playstation_vita = {}
sony_playstation_vita[keys.platform_key_supercategory] = categories.game_supercategory_roms
sony_playstation_vita[keys.platform_key_category] = categories.game_category_sony
sony_playstation_vita[keys.platform_key_subcategory] = "Sony PlayStation Vita"
sony_playstation_vita[keys.platform_key_transforms] = []
sony_playstation_vita[keys.platform_key_addons] = [types.addon_type_dlc, types.addon_type_updates]
sony_playstation_vita[keys.platform_key_launcher] = [types.launch_type_name]
platforms["Sony PlayStation Vita"] = sony_playstation_vita
