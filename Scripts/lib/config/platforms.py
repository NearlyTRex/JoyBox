# Imports
import os
import sys

# Keys
key_supercategory = "supercategory"
key_category = "category"
key_subcategory = "subcategory"
key_transforms = "transforms"
key_addons = "addons"
key_launcher = "launcher"

# Transform types
transform_type_exe_to_install = "exe_to_install"
transform_type_exe_to_raw_plain = "exe_to_raw_plain"
transform_type_chd_to_iso = "chd_to_iso"
transform_type_iso_to_xiso = "iso_to_xiso"
transform_type_iso_to_raw_ps3 = "iso_to_raw_ps3"
transform_type_pkg_to_raw_ps3 = "pkg_to_raw_ps3"
transform_type_pkg_to_raw_psv = "pkg_to_raw_psv"

# Addon types
addon_type_dlc = "dlc"
addon_type_updates = "updates"

# Launch types
launch_type_none = "no_launcher"
launch_type_file = "launch_file"
launch_type_name = "launch_name"

# Platforms
platforms = {}

######################################################################################

###########################################################
# Computer - Amazon Games
###########################################################
computer_amazon_games = {}
computer_amazon_games[key_supercategory] = "Roms"
computer_amazon_games[key_category] = "Computer"
computer_amazon_games[key_subcategory] = "Amazon Games"
computer_amazon_games[key_transforms] = [transform_type_exe_to_raw_plain]
computer_amazon_games[key_addons] = []
computer_amazon_games[key_launcher] = [launch_type_file]
platforms["Computer - Amazon Games"] = computer_amazon_games

###########################################################
# Computer - Disc
###########################################################
computer_disc = {}
computer_disc[key_supercategory] = "Roms"
computer_disc[key_category] = "Computer"
computer_disc[key_subcategory] = "Disc"
computer_disc[key_transforms] = [transform_type_exe_to_install]
computer_disc[key_addons] = []
computer_disc[key_launcher] = [launch_type_file]
platforms["Computer - Disc"] = computer_disc

###########################################################
# Computer - Epic Games
###########################################################
computer_epic_games = {}
computer_epic_games[key_supercategory] = "Roms"
computer_epic_games[key_category] = "Computer"
computer_epic_games[key_subcategory] = "Epic Games"
computer_epic_games[key_transforms] = [transform_type_exe_to_raw_plain]
computer_epic_games[key_addons] = []
computer_epic_games[key_launcher] = [launch_type_file]
platforms["Computer - Epic Games"] = computer_epic_games

###########################################################
# Computer - GOG
###########################################################
computer_gog = {}
computer_gog[key_supercategory] = "Roms"
computer_gog[key_category] = "Computer"
computer_gog[key_subcategory] = "GOG"
computer_gog[key_transforms] = [transform_type_exe_to_install]
computer_gog[key_addons] = []
computer_gog[key_launcher] = [launch_type_file]
platforms["Computer - GOG"] = computer_gog

###########################################################
# Computer - Humble Bundle
###########################################################
computer_humble_bundle = {}
computer_humble_bundle[key_supercategory] = "Roms"
computer_humble_bundle[key_category] = "Computer"
computer_humble_bundle[key_subcategory] = "Humble Bundle"
computer_humble_bundle[key_transforms] = [transform_type_exe_to_install]
computer_humble_bundle[key_addons] = []
computer_humble_bundle[key_launcher] = [launch_type_file]
platforms["Computer - Humble Bundle"] = computer_humble_bundle

###########################################################
# Computer - Itchio
###########################################################
computer_itchio = {}
computer_itchio[key_supercategory] = "Roms"
computer_itchio[key_category] = "Computer"
computer_itchio[key_subcategory] = "Itchio"
computer_itchio[key_transforms] = [transform_type_exe_to_raw_plain]
computer_itchio[key_addons] = []
computer_itchio[key_launcher] = [launch_type_file]
platforms["Computer - Itchio"] = computer_itchio

###########################################################
# Computer - Puppet Combo
###########################################################
computer_puppet_combo = {}
computer_puppet_combo[key_supercategory] = "Roms"
computer_puppet_combo[key_category] = "Computer"
computer_puppet_combo[key_subcategory] = "Puppet Combo"
computer_puppet_combo[key_transforms] = [transform_type_exe_to_raw_plain]
computer_puppet_combo[key_addons] = []
computer_puppet_combo[key_launcher] = [launch_type_file]
platforms["Computer - Puppet Combo"] = computer_puppet_combo

###########################################################
# Computer - Red Candle
###########################################################
computer_red_candle = {}
computer_red_candle[key_supercategory] = "Roms"
computer_red_candle[key_category] = "Computer"
computer_red_candle[key_subcategory] = "Red Candle"
computer_red_candle[key_transforms] = [transform_type_exe_to_install]
computer_red_candle[key_addons] = []
computer_red_candle[key_launcher] = [launch_type_file]
platforms["Computer - Red Candle"] = computer_red_candle

###########################################################
# Computer - Square Enix
###########################################################
computer_square_enix = {}
computer_square_enix[key_supercategory] = "Roms"
computer_square_enix[key_category] = "Computer"
computer_square_enix[key_subcategory] = "Square Enix"
computer_square_enix[key_transforms] = [transform_type_exe_to_install]
computer_square_enix[key_addons] = []
computer_square_enix[key_launcher] = [launch_type_file]
platforms["Computer - Square Enix"] = computer_square_enix

###########################################################
# Computer - Steam
###########################################################
computer_steam = {}
computer_steam[key_supercategory] = "Roms"
computer_steam[key_category] = "Computer"
computer_steam[key_subcategory] = "Steam"
computer_steam[key_transforms] = [transform_type_exe_to_raw_plain]
computer_steam[key_addons] = []
computer_steam[key_launcher] = [launch_type_file]
platforms["Computer - Steam"] = computer_steam

###########################################################
# Computer - Zoom
###########################################################
computer_zoom = {}
computer_zoom[key_supercategory] = "Roms"
computer_zoom[key_category] = "Computer"
computer_zoom[key_subcategory] = "Zoom"
computer_zoom[key_transforms] = [transform_type_exe_to_install]
computer_zoom[key_addons] = []
computer_zoom[key_launcher] = [launch_type_file]
platforms["Computer - Zoom"] = computer_zoom

######################################################################################

###########################################################
# Microsoft MSX
###########################################################
microsoft_msx = {}
microsoft_msx[key_supercategory] = "Roms"
microsoft_msx[key_category] = "Microsoft"
microsoft_msx[key_subcategory] = "Microsoft MSX"
microsoft_msx[key_transforms] = []
microsoft_msx[key_addons] = []
microsoft_msx[key_launcher] = [launch_type_file]
platforms["Microsoft MSX"] = microsoft_msx

###########################################################
# Microsoft Xbox
###########################################################
microsoft_xbox = {}
microsoft_xbox[key_supercategory] = "Roms"
microsoft_xbox[key_category] = "Microsoft"
microsoft_xbox[key_subcategory] = "Microsoft Xbox"
microsoft_xbox[key_transforms] = [transform_type_chd_to_iso, transform_type_iso_to_xiso]
microsoft_xbox[key_addons] = []
microsoft_xbox[key_launcher] = [launch_type_file]
platforms["Microsoft Xbox"] = microsoft_xbox

###########################################################
# Microsoft Xbox 360
###########################################################
microsoft_xbox_360 = {}
microsoft_xbox_360[key_supercategory] = "Roms"
microsoft_xbox_360[key_category] = "Microsoft"
microsoft_xbox_360[key_subcategory] = "Microsoft Xbox 360"
microsoft_xbox_360[key_transforms] = [transform_type_chd_to_iso, transform_type_iso_to_xiso]
microsoft_xbox_360[key_addons] = [addon_type_dlc, addon_type_updates]
microsoft_xbox_360[key_launcher] = [launch_type_file]
platforms["Microsoft Xbox 360"] = microsoft_xbox_360

###########################################################
# Microsoft Xbox 360 GOD
###########################################################
microsoft_xbox_360_god = {}
microsoft_xbox_360_god[key_supercategory] = "Roms"
microsoft_xbox_360_god[key_category] = "Microsoft"
microsoft_xbox_360_god[key_subcategory] = "Microsoft Xbox 360 GOD"
microsoft_xbox_360_god[key_transforms] = []
microsoft_xbox_360_god[key_addons] = [addon_type_dlc, addon_type_updates]
microsoft_xbox_360_god[key_launcher] = [launch_type_file]
platforms["Microsoft Xbox 360 GOD"] = microsoft_xbox_360_god

###########################################################
# Microsoft Xbox 360 XBLA
###########################################################
microsoft_xbox_360_xbla = {}
microsoft_xbox_360_xbla[key_supercategory] = "Roms"
microsoft_xbox_360_xbla[key_category] = "Microsoft"
microsoft_xbox_360_xbla[key_subcategory] = "Microsoft Xbox 360 XBLA"
microsoft_xbox_360_xbla[key_transforms] = []
microsoft_xbox_360_xbla[key_addons] = [addon_type_dlc, addon_type_updates]
microsoft_xbox_360_xbla[key_launcher] = [launch_type_file]
platforms["Microsoft Xbox 360 XBLA"] = microsoft_xbox_360_xbla

###########################################################
# Microsoft Xbox 360 XIG
###########################################################
microsoft_xbox_360_xig = {}
microsoft_xbox_360_xig[key_supercategory] = "Roms"
microsoft_xbox_360_xig[key_category] = "Microsoft"
microsoft_xbox_360_xig[key_subcategory] = "Microsoft Xbox 360 XIG"
microsoft_xbox_360_xig[key_transforms] = []
microsoft_xbox_360_xig[key_addons] = []
microsoft_xbox_360_xig[key_launcher] = [launch_type_file]
platforms["Microsoft Xbox 360 XIG"] = microsoft_xbox_360_xig

###########################################################
# Microsoft Xbox One
###########################################################
microsoft_xbox_one = {}
microsoft_xbox_one[key_supercategory] = "Roms"
microsoft_xbox_one[key_category] = "Microsoft"
microsoft_xbox_one[key_subcategory] = "Microsoft Xbox One"
microsoft_xbox_one[key_transforms] = []
microsoft_xbox_one[key_addons] = []
microsoft_xbox_one[key_launcher] = [launch_type_none]
platforms["Microsoft Xbox One"] = microsoft_xbox_one

###########################################################
# Microsoft Xbox One GOD
###########################################################
microsoft_xbox_one_god = {}
microsoft_xbox_one_god[key_supercategory] = "Roms"
microsoft_xbox_one_god[key_category] = "Microsoft"
microsoft_xbox_one_god[key_subcategory] = "Microsoft Xbox One GOD"
microsoft_xbox_one_god[key_transforms] = []
microsoft_xbox_one_god[key_addons] = []
microsoft_xbox_one_god[key_launcher] = [launch_type_none]
platforms["Microsoft Xbox One GOD"] = microsoft_xbox_one_god

######################################################################################

###########################################################
# Nintendo 3DS
###########################################################
nintendo_3ds = {}
nintendo_3ds[key_supercategory] = "Roms"
nintendo_3ds[key_category] = "Nintendo"
nintendo_3ds[key_subcategory] = "Nintendo 3DS"
nintendo_3ds[key_transforms] = []
nintendo_3ds[key_addons] = [addon_type_dlc, addon_type_updates]
nintendo_3ds[key_launcher] = [launch_type_file]
platforms["Nintendo 3DS"] = nintendo_3ds

###########################################################
# Nintendo 3DS Apps
###########################################################
nintendo_3ds_apps = {}
nintendo_3ds_apps[key_supercategory] = "Roms"
nintendo_3ds_apps[key_category] = "Nintendo"
nintendo_3ds_apps[key_subcategory] = "Nintendo 3DS Apps"
nintendo_3ds_apps[key_transforms] = []
nintendo_3ds_apps[key_addons] = []
nintendo_3ds_apps[key_launcher] = [launch_type_file]
platforms["Nintendo 3DS Apps"] = nintendo_3ds_apps

###########################################################
# Nintendo 3DS eShop
###########################################################
nintendo_3ds_eshop = {}
nintendo_3ds_eshop[key_supercategory] = "Roms"
nintendo_3ds_eshop[key_category] = "Nintendo"
nintendo_3ds_eshop[key_subcategory] = "Nintendo 3DS eShop"
nintendo_3ds_eshop[key_transforms] = []
nintendo_3ds_eshop[key_addons] = [addon_type_dlc, addon_type_updates]
nintendo_3ds_eshop[key_launcher] = [launch_type_file]
platforms["Nintendo 3DS eShop"] = nintendo_3ds_eshop

###########################################################
# Nintendo 64
###########################################################
nintendo_64 = {}
nintendo_64[key_supercategory] = "Roms"
nintendo_64[key_category] = "Nintendo"
nintendo_64[key_subcategory] = "Nintendo 64"
nintendo_64[key_transforms] = []
nintendo_64[key_addons] = []
nintendo_64[key_launcher] = [launch_type_file]
platforms["Nintendo 64"] = nintendo_64

###########################################################
# Nintendo DS
###########################################################
nintendo_ds = {}
nintendo_ds[key_supercategory] = "Roms"
nintendo_ds[key_category] = "Nintendo"
nintendo_ds[key_subcategory] = "Nintendo DS"
nintendo_ds[key_transforms] = []
nintendo_ds[key_addons] = []
nintendo_ds[key_launcher] = [launch_type_file]
platforms["Nintendo DS"] = nintendo_ds

###########################################################
# Nintendo DSi
###########################################################
nintendo_dsi = {}
nintendo_dsi[key_supercategory] = "Roms"
nintendo_dsi[key_category] = "Nintendo"
nintendo_dsi[key_subcategory] = "Nintendo DSi"
nintendo_dsi[key_transforms] = []
nintendo_dsi[key_addons] = []
nintendo_dsi[key_launcher] = [launch_type_file]
platforms["Nintendo DSi"] = nintendo_dsi

###########################################################
# Nintendo Famicom
###########################################################
nintendo_famicom = {}
nintendo_famicom[key_supercategory] = "Roms"
nintendo_famicom[key_category] = "Nintendo"
nintendo_famicom[key_subcategory] = "Nintendo Famicom"
nintendo_famicom[key_transforms] = []
nintendo_famicom[key_addons] = []
nintendo_famicom[key_launcher] = [launch_type_file]
platforms["Nintendo Famicom"] = nintendo_famicom

###########################################################
# Nintendo Game Boy
###########################################################
nintendo_game_boy = {}
nintendo_game_boy[key_supercategory] = "Roms"
nintendo_game_boy[key_category] = "Nintendo"
nintendo_game_boy[key_subcategory] = "Nintendo Game Boy"
nintendo_game_boy[key_transforms] = []
nintendo_game_boy[key_addons] = []
nintendo_game_boy[key_launcher] = [launch_type_file]
platforms["Nintendo Game Boy"] = nintendo_game_boy

###########################################################
# Nintendo Game Boy Advance
###########################################################
nintendo_game_boy_advance = {}
nintendo_game_boy_advance[key_supercategory] = "Roms"
nintendo_game_boy_advance[key_category] = "Nintendo"
nintendo_game_boy_advance[key_subcategory] = "Nintendo Game Boy Advance"
nintendo_game_boy_advance[key_transforms] = []
nintendo_game_boy_advance[key_addons] = []
nintendo_game_boy_advance[key_launcher] = [launch_type_file]
platforms["Nintendo Game Boy Advance"] = nintendo_game_boy_advance

###########################################################
# Nintendo Game Boy Advance e-Reader
###########################################################
nintendo_game_boy_advance_ereader = {}
nintendo_game_boy_advance_ereader[key_supercategory] = "Roms"
nintendo_game_boy_advance_ereader[key_category] = "Nintendo"
nintendo_game_boy_advance_ereader[key_subcategory] = "Nintendo Game Boy Advance e-Reader"
nintendo_game_boy_advance_ereader[key_transforms] = []
nintendo_game_boy_advance_ereader[key_addons] = []
nintendo_game_boy_advance_ereader[key_launcher] = [launch_type_file]
platforms["Nintendo Game Boy Advance e-Reader"] = nintendo_game_boy_advance_ereader

###########################################################
# Nintendo Game Boy Color
###########################################################
nintendo_game_boy_color = {}
nintendo_game_boy_color[key_supercategory] = "Roms"
nintendo_game_boy_color[key_category] = "Nintendo"
nintendo_game_boy_color[key_subcategory] = "Nintendo Game Boy Color"
nintendo_game_boy_color[key_transforms] = []
nintendo_game_boy_color[key_addons] = []
nintendo_game_boy_color[key_launcher] = [launch_type_file]
platforms["Nintendo Game Boy Color"] = nintendo_game_boy_color

###########################################################
# Nintendo Gamecube
###########################################################
nintendo_gamecube = {}
nintendo_gamecube[key_supercategory] = "Roms"
nintendo_gamecube[key_category] = "Nintendo"
nintendo_gamecube[key_subcategory] = "Nintendo Gamecube"
nintendo_gamecube[key_transforms] = []
nintendo_gamecube[key_addons] = []
nintendo_gamecube[key_launcher] = [launch_type_file]
platforms["Nintendo Gamecube"] = nintendo_gamecube

###########################################################
# Nintendo NES
###########################################################
nintendo_nes = {}
nintendo_nes[key_supercategory] = "Roms"
nintendo_nes[key_category] = "Nintendo"
nintendo_nes[key_subcategory] = "Nintendo NES"
nintendo_nes[key_transforms] = []
nintendo_nes[key_addons] = []
nintendo_nes[key_launcher] = [launch_type_file]
platforms["Nintendo NES"] = nintendo_nes

###########################################################
# Nintendo SNES
###########################################################
nintendo_snes = {}
nintendo_snes[key_supercategory] = "Roms"
nintendo_snes[key_category] = "Nintendo"
nintendo_snes[key_subcategory] = "Nintendo SNES"
nintendo_snes[key_transforms] = []
nintendo_snes[key_addons] = []
nintendo_snes[key_launcher] = [launch_type_file]
platforms["Nintendo SNES"] = nintendo_snes

###########################################################
# Nintendo Super Famicom
###########################################################
nintendo_super_famicom = {}
nintendo_super_famicom[key_supercategory] = "Roms"
nintendo_super_famicom[key_category] = "Nintendo"
nintendo_super_famicom[key_subcategory] = "Nintendo Super Famicom"
nintendo_super_famicom[key_transforms] = []
nintendo_super_famicom[key_addons] = []
nintendo_super_famicom[key_launcher] = [launch_type_file]
platforms["Nintendo Super Famicom"] = nintendo_super_famicom

###########################################################
# Nintendo Super Game Boy
###########################################################
nintendo_super_game_boy = {}
nintendo_super_game_boy[key_supercategory] = "Roms"
nintendo_super_game_boy[key_category] = "Nintendo"
nintendo_super_game_boy[key_subcategory] = "Nintendo Super Game Boy"
nintendo_super_game_boy[key_transforms] = []
nintendo_super_game_boy[key_addons] = []
nintendo_super_game_boy[key_launcher] = [launch_type_file]
platforms["Nintendo Super Game Boy"] = nintendo_super_game_boy

###########################################################
# Nintendo Super Game Boy Color
###########################################################
nintendo_super_game_boy_color = {}
nintendo_super_game_boy_color[key_supercategory] = "Roms"
nintendo_super_game_boy_color[key_category] = "Nintendo"
nintendo_super_game_boy_color[key_subcategory] = "Nintendo Super Game Boy Color"
nintendo_super_game_boy_color[key_transforms] = []
nintendo_super_game_boy_color[key_addons] = []
nintendo_super_game_boy_color[key_launcher] = [launch_type_file]
platforms["Nintendo Super Game Boy Color"] = nintendo_super_game_boy_color

###########################################################
# Nintendo Switch
###########################################################
nintendo_switch = {}
nintendo_switch[key_supercategory] = "Roms"
nintendo_switch[key_category] = "Nintendo"
nintendo_switch[key_subcategory] = "Nintendo Switch"
nintendo_switch[key_transforms] = []
nintendo_switch[key_addons] = [addon_type_dlc, addon_type_updates]
nintendo_switch[key_launcher] = [launch_type_file]
platforms["Nintendo Switch"] = nintendo_switch

###########################################################
# Nintendo Switch eShop
###########################################################
nintendo_switch_eshop = {}
nintendo_switch_eshop[key_supercategory] = "Roms"
nintendo_switch_eshop[key_category] = "Nintendo"
nintendo_switch_eshop[key_subcategory] = "Nintendo Switch eShop"
nintendo_switch_eshop[key_transforms] = []
nintendo_switch_eshop[key_addons] = [addon_type_dlc, addon_type_updates]
nintendo_switch_eshop[key_launcher] = [launch_type_file]
platforms["Nintendo Switch eShop"] = nintendo_switch_eshop

###########################################################
# Nintendo Virtual Boy
###########################################################
nintendo_virtual_boy = {}
nintendo_virtual_boy[key_supercategory] = "Roms"
nintendo_virtual_boy[key_category] = "Nintendo"
nintendo_virtual_boy[key_subcategory] = "Nintendo Virtual Boy"
nintendo_virtual_boy[key_transforms] = []
nintendo_virtual_boy[key_addons] = []
nintendo_virtual_boy[key_launcher] = [launch_type_file]
platforms["Nintendo Virtual Boy"] = nintendo_virtual_boy

###########################################################
# Nintendo Wii
###########################################################
nintendo_wii = {}
nintendo_wii[key_supercategory] = "Roms"
nintendo_wii[key_category] = "Nintendo"
nintendo_wii[key_subcategory] = "Nintendo Wii"
nintendo_wii[key_transforms] = []
nintendo_wii[key_addons] = [addon_type_dlc]
nintendo_wii[key_launcher] = [launch_type_file]
platforms["Nintendo Wii"] = nintendo_wii

###########################################################
# Nintendo Wii U
###########################################################
nintendo_wii_u = {}
nintendo_wii_u[key_supercategory] = "Roms"
nintendo_wii_u[key_category] = "Nintendo"
nintendo_wii_u[key_subcategory] = "Nintendo Wii U"
nintendo_wii_u[key_transforms] = []
nintendo_wii_u[key_addons] = [addon_type_dlc, addon_type_updates]
nintendo_wii_u[key_launcher] = [launch_type_file]
platforms["Nintendo Wii U"] = nintendo_wii_u

###########################################################
# Nintendo Wii U eShop
###########################################################
nintendo_wii_u_eshop = {}
nintendo_wii_u_eshop[key_supercategory] = "Roms"
nintendo_wii_u_eshop[key_category] = "Nintendo"
nintendo_wii_u_eshop[key_subcategory] = "Nintendo Wii U eShop"
nintendo_wii_u_eshop[key_transforms] = []
nintendo_wii_u_eshop[key_addons] = [addon_type_dlc, addon_type_updates]
nintendo_wii_u_eshop[key_launcher] = [launch_type_file]
platforms["Nintendo Wii U eShop"] = nintendo_wii_u_eshop

######################################################################################

###########################################################
# Apple iOS
###########################################################
apple_ios = {}
apple_ios[key_supercategory] = "Roms"
apple_ios[key_category] = "Other"
apple_ios[key_subcategory] = "Apple iOS"
apple_ios[key_transforms] = []
apple_ios[key_addons] = []
apple_ios[key_launcher] = [launch_type_none]
platforms["Apple iOS"] = apple_ios

###########################################################
# Apple MacOS 8
###########################################################
apple_macos_8 = {}
apple_macos_8[key_supercategory] = "Roms"
apple_macos_8[key_category] = "Other"
apple_macos_8[key_subcategory] = "Apple MacOS 8"
apple_macos_8[key_transforms] = []
apple_macos_8[key_addons] = []
apple_macos_8[key_launcher] = [launch_type_file]
platforms["Apple MacOS 8"] = apple_macos_8

###########################################################
# Arcade
###########################################################
arcade = {}
arcade[key_supercategory] = "Roms"
arcade[key_category] = "Other"
arcade[key_subcategory] = "Arcade"
arcade[key_transforms] = []
arcade[key_addons] = []
arcade[key_launcher] = [launch_type_name]
platforms["Arcade"] = arcade

###########################################################
# Atari 800
###########################################################
atari_800 = {}
atari_800[key_supercategory] = "Roms"
atari_800[key_category] = "Other"
atari_800[key_subcategory] = "Atari 800"
atari_800[key_transforms] = []
atari_800[key_addons] = []
atari_800[key_launcher] = [launch_type_file]
platforms["Atari 800"] = atari_800

###########################################################
# Atari 2600
###########################################################
atari_2600 = {}
atari_2600[key_supercategory] = "Roms"
atari_2600[key_category] = "Other"
atari_2600[key_subcategory] = "Atari 2600"
atari_2600[key_transforms] = []
atari_2600[key_addons] = []
atari_2600[key_launcher] = [launch_type_file]
platforms["Atari 2600"] = atari_2600

###########################################################
# Atari 5200
###########################################################
atari_5200 = {}
atari_5200[key_supercategory] = "Roms"
atari_5200[key_category] = "Other"
atari_5200[key_subcategory] = "Atari 5200"
atari_5200[key_transforms] = []
atari_5200[key_addons] = []
atari_5200[key_launcher] = [launch_type_file]
platforms["Atari 5200"] = atari_5200

###########################################################
# Atari 7800
###########################################################
atari_7800 = {}
atari_7800[key_supercategory] = "Roms"
atari_7800[key_category] = "Other"
atari_7800[key_subcategory] = "Atari 7800"
atari_7800[key_transforms] = []
atari_7800[key_addons] = []
atari_7800[key_launcher] = [launch_type_file]
platforms["Atari 7800"] = atari_7800

###########################################################
# Atari Jaguar
###########################################################
atari_jaguar = {}
atari_jaguar[key_supercategory] = "Roms"
atari_jaguar[key_category] = "Other"
atari_jaguar[key_subcategory] = "Atari Jaguar"
atari_jaguar[key_transforms] = []
atari_jaguar[key_addons] = []
atari_jaguar[key_launcher] = [launch_type_file]
platforms["Atari Jaguar"] = atari_jaguar

###########################################################
# Atari Jaguar CD
###########################################################
atari_jaguar_cd = {}
atari_jaguar_cd[key_supercategory] = "Roms"
atari_jaguar_cd[key_category] = "Other"
atari_jaguar_cd[key_subcategory] = "Atari Jaguar CD"
atari_jaguar_cd[key_transforms] = []
atari_jaguar_cd[key_addons] = []
atari_jaguar_cd[key_launcher] = [launch_type_file]
platforms["Atari Jaguar CD"] = atari_jaguar_cd

###########################################################
# Atari Lynx
###########################################################
atari_lynx = {}
atari_lynx[key_supercategory] = "Roms"
atari_lynx[key_category] = "Other"
atari_lynx[key_subcategory] = "Atari Lynx"
atari_lynx[key_transforms] = []
atari_lynx[key_addons] = []
atari_lynx[key_launcher] = [launch_type_file]
platforms["Atari Lynx"] = atari_lynx

###########################################################
# Bandai WonderSwan
###########################################################
bandai_wonderswan = {}
bandai_wonderswan[key_supercategory] = "Roms"
bandai_wonderswan[key_category] = "Other"
bandai_wonderswan[key_subcategory] = "Bandai WonderSwan"
bandai_wonderswan[key_transforms] = []
bandai_wonderswan[key_addons] = []
bandai_wonderswan[key_launcher] = [launch_type_file]
platforms["Bandai WonderSwan"] = bandai_wonderswan

###########################################################
# Bandai WonderSwan Color
###########################################################
bandai_wonderswan_color = {}
bandai_wonderswan_color[key_supercategory] = "Roms"
bandai_wonderswan_color[key_category] = "Other"
bandai_wonderswan_color[key_subcategory] = "Bandai WonderSwan Color"
bandai_wonderswan_color[key_transforms] = []
bandai_wonderswan_color[key_addons] = []
bandai_wonderswan_color[key_launcher] = [launch_type_file]
platforms["Bandai WonderSwan Color"] = bandai_wonderswan_color

###########################################################
# Coleco ColecoVision
###########################################################
coleco_colecovision = {}
coleco_colecovision[key_supercategory] = "Roms"
coleco_colecovision[key_category] = "Other"
coleco_colecovision[key_subcategory] = "Coleco ColecoVision"
coleco_colecovision[key_transforms] = []
coleco_colecovision[key_addons] = []
coleco_colecovision[key_launcher] = [launch_type_file]
platforms["Coleco ColecoVision"] = coleco_colecovision

###########################################################
# Commodore 64
###########################################################
commodore_64 = {}
commodore_64[key_supercategory] = "Roms"
commodore_64[key_category] = "Other"
commodore_64[key_subcategory] = "Commodore 64"
commodore_64[key_transforms] = []
commodore_64[key_addons] = []
commodore_64[key_launcher] = [launch_type_file]
platforms["Commodore 64"] = commodore_64

###########################################################
# Commodore Amiga
###########################################################
commodore_amiga = {}
commodore_amiga[key_supercategory] = "Roms"
commodore_amiga[key_category] = "Other"
commodore_amiga[key_subcategory] = "Commodore Amiga"
commodore_amiga[key_transforms] = []
commodore_amiga[key_addons] = []
commodore_amiga[key_launcher] = [launch_type_file]
platforms["Commodore Amiga"] = commodore_amiga

###########################################################
# Google Android
###########################################################
google_android = {}
google_android[key_supercategory] = "Roms"
google_android[key_category] = "Other"
google_android[key_subcategory] = "Google Android"
google_android[key_transforms] = []
google_android[key_addons] = []
google_android[key_launcher] = [launch_type_none]
platforms["Google Android"] = google_android

###########################################################
# Magnavox Odyssey 2
###########################################################
magnavox_odyssey_2 = {}
magnavox_odyssey_2[key_supercategory] = "Roms"
magnavox_odyssey_2[key_category] = "Other"
magnavox_odyssey_2[key_subcategory] = "Magnavox Odyssey 2"
magnavox_odyssey_2[key_transforms] = []
magnavox_odyssey_2[key_addons] = []
magnavox_odyssey_2[key_launcher] = [launch_type_file]
platforms["Magnavox Odyssey 2"] = magnavox_odyssey_2

###########################################################
# Mattel Intellivision
###########################################################
mattel_intellivision = {}
mattel_intellivision[key_supercategory] = "Roms"
mattel_intellivision[key_category] = "Other"
mattel_intellivision[key_subcategory] = "Mattel Intellivision"
mattel_intellivision[key_transforms] = []
mattel_intellivision[key_addons] = []
mattel_intellivision[key_launcher] = [launch_type_file]
platforms["Mattel Intellivision"] = mattel_intellivision

###########################################################
# NEC SuperGrafx
###########################################################
nec_supergrafx = {}
nec_supergrafx[key_supercategory] = "Roms"
nec_supergrafx[key_category] = "Other"
nec_supergrafx[key_subcategory] = "NEC SuperGrafx"
nec_supergrafx[key_transforms] = []
nec_supergrafx[key_addons] = []
nec_supergrafx[key_launcher] = [launch_type_file]
platforms["NEC SuperGrafx"] = nec_supergrafx

###########################################################
# NEC TurboGrafx CD & PC-Engine CD
###########################################################
nec_turbografx_pcengine_cd = {}
nec_turbografx_pcengine_cd[key_supercategory] = "Roms"
nec_turbografx_pcengine_cd[key_category] = "Other"
nec_turbografx_pcengine_cd[key_subcategory] = "NEC TurboGrafx CD & PC-Engine CD"
nec_turbografx_pcengine_cd[key_transforms] = []
nec_turbografx_pcengine_cd[key_addons] = []
nec_turbografx_pcengine_cd[key_launcher] = [launch_type_file]
platforms["NEC TurboGrafx CD & PC-Engine CD"] = nec_turbografx_pcengine_cd

###########################################################
# NEC TurboGrafx-16 & PC-Engine
###########################################################
nec_turbografx_pcengine = {}
nec_turbografx_pcengine[key_supercategory] = "Roms"
nec_turbografx_pcengine[key_category] = "Other"
nec_turbografx_pcengine[key_subcategory] = "NEC TurboGrafx-16 & PC-Engine"
nec_turbografx_pcengine[key_transforms] = []
nec_turbografx_pcengine[key_addons] = []
nec_turbografx_pcengine[key_launcher] = [launch_type_file]
platforms["NEC TurboGrafx-16 & PC-Engine"] = nec_turbografx_pcengine

###########################################################
# Nokia N-Gage
###########################################################
nokia_ngage = {}
nokia_ngage[key_supercategory] = "Roms"
nokia_ngage[key_category] = "Other"
nokia_ngage[key_subcategory] = "Nokia N-Gage"
nokia_ngage[key_transforms] = []
nokia_ngage[key_addons] = []
nokia_ngage[key_launcher] = [launch_type_name]
platforms["Nokia N-Gage"] = nokia_ngage

###########################################################
# Panasonic 3DO
###########################################################
panasonic_3do = {}
panasonic_3do[key_supercategory] = "Roms"
panasonic_3do[key_category] = "Other"
panasonic_3do[key_subcategory] = "Panasonic 3DO"
panasonic_3do[key_transforms] = []
panasonic_3do[key_addons] = []
panasonic_3do[key_launcher] = [launch_type_file]
platforms["Panasonic 3DO"] = panasonic_3do

###########################################################
# Philips CDi
###########################################################
philips_cdi = {}
philips_cdi[key_supercategory] = "Roms"
philips_cdi[key_category] = "Other"
philips_cdi[key_subcategory] = "Philips CDi"
philips_cdi[key_transforms] = []
philips_cdi[key_addons] = []
philips_cdi[key_launcher] = [launch_type_file]
platforms["Philips CDi"] = philips_cdi

###########################################################
# SNK Neo Geo Pocket Color
###########################################################
snk_neogeo_pocket_color = {}
snk_neogeo_pocket_color[key_supercategory] = "Roms"
snk_neogeo_pocket_color[key_category] = "Other"
snk_neogeo_pocket_color[key_subcategory] = "SNK Neo Geo Pocket Color"
snk_neogeo_pocket_color[key_transforms] = []
snk_neogeo_pocket_color[key_addons] = []
snk_neogeo_pocket_color[key_launcher] = [launch_type_file]
platforms["SNK Neo Geo Pocket Color"] = snk_neogeo_pocket_color

###########################################################
# Sega 32X
###########################################################
sega_32x = {}
sega_32x[key_supercategory] = "Roms"
sega_32x[key_category] = "Other"
sega_32x[key_subcategory] = "Sega 32X"
sega_32x[key_transforms] = []
sega_32x[key_addons] = []
sega_32x[key_launcher] = [launch_type_file]
platforms["Sega 32X"] = sega_32x

###########################################################
# Sega CD
###########################################################
sega_cd = {}
sega_cd[key_supercategory] = "Roms"
sega_cd[key_category] = "Other"
sega_cd[key_subcategory] = "Sega CD"
sega_cd[key_transforms] = []
sega_cd[key_addons] = []
sega_cd[key_launcher] = [launch_type_file]
platforms["Sega CD"] = sega_cd

###########################################################
# Sega CD 32X
###########################################################
sega_cd_32x = {}
sega_cd_32x[key_supercategory] = "Roms"
sega_cd_32x[key_category] = "Other"
sega_cd_32x[key_subcategory] = "Sega CD 32X"
sega_cd_32x[key_transforms] = []
sega_cd_32x[key_addons] = []
sega_cd_32x[key_launcher] = [launch_type_file]
platforms["Sega CD 32X"] = sega_cd_32x

###########################################################
# Sega Dreamcast
###########################################################
sega_dreamcast = {}
sega_dreamcast[key_supercategory] = "Roms"
sega_dreamcast[key_category] = "Other"
sega_dreamcast[key_subcategory] = "Sega Dreamcast"
sega_dreamcast[key_transforms] = []
sega_dreamcast[key_addons] = []
sega_dreamcast[key_launcher] = [launch_type_file]
platforms["Sega Dreamcast"] = sega_dreamcast

###########################################################
# Sega Game Gear
###########################################################
sega_game_gear = {}
sega_game_gear[key_supercategory] = "Roms"
sega_game_gear[key_category] = "Other"
sega_game_gear[key_subcategory] = "Sega Game Gear"
sega_game_gear[key_transforms] = []
sega_game_gear[key_addons] = []
sega_game_gear[key_launcher] = [launch_type_file]
platforms["Sega Game Gear"] = sega_game_gear

###########################################################
# Sega Genesis
###########################################################
sega_genesis = {}
sega_genesis[key_supercategory] = "Roms"
sega_genesis[key_category] = "Other"
sega_genesis[key_subcategory] = "Sega Genesis"
sega_genesis[key_transforms] = []
sega_genesis[key_addons] = []
sega_genesis[key_launcher] = [launch_type_file]
platforms["Sega Genesis"] = sega_genesis

###########################################################
# Sega Master System
###########################################################
sega_master_system = {}
sega_master_system[key_supercategory] = "Roms"
sega_master_system[key_category] = "Other"
sega_master_system[key_subcategory] = "Sega Master System"
sega_master_system[key_transforms] = []
sega_master_system[key_addons] = []
sega_master_system[key_launcher] = [launch_type_file]
platforms["Sega Master System"] = sega_master_system

###########################################################
# Sega Saturn
###########################################################
sega_saturn = {}
sega_saturn[key_supercategory] = "Roms"
sega_saturn[key_category] = "Other"
sega_saturn[key_subcategory] = "Sega Saturn"
sega_saturn[key_transforms] = []
sega_saturn[key_addons] = []
sega_saturn[key_launcher] = [launch_type_file]
platforms["Sega Saturn"] = sega_saturn

###########################################################
# Sinclair ZX Spectrum
###########################################################
sinclair_zx_spectrum = {}
sinclair_zx_spectrum[key_supercategory] = "Roms"
sinclair_zx_spectrum[key_category] = "Other"
sinclair_zx_spectrum[key_subcategory] = "Sinclair ZX Spectrum"
sinclair_zx_spectrum[key_transforms] = []
sinclair_zx_spectrum[key_addons] = []
sinclair_zx_spectrum[key_launcher] = [launch_type_file]
platforms["Sinclair ZX Spectrum"] = sinclair_zx_spectrum

###########################################################
# Texas Instruments TI-99-4A
###########################################################
texas_instruments_ti994a = {}
texas_instruments_ti994a[key_supercategory] = "Roms"
texas_instruments_ti994a[key_category] = "Other"
texas_instruments_ti994a[key_subcategory] = "Texas Instruments TI-99-4A"
texas_instruments_ti994a[key_transforms] = []
texas_instruments_ti994a[key_addons] = []
texas_instruments_ti994a[key_launcher] = [launch_type_file]
platforms["Texas Instruments TI-99-4A"] = texas_instruments_ti994a

###########################################################
# Tiger Game.com
###########################################################
tiger_gamecom = {}
tiger_gamecom[key_supercategory] = "Roms"
tiger_gamecom[key_category] = "Other"
tiger_gamecom[key_subcategory] = "Tiger Game.com"
tiger_gamecom[key_transforms] = []
tiger_gamecom[key_addons] = []
tiger_gamecom[key_launcher] = [launch_type_file]
platforms["Tiger Game.com"] = tiger_gamecom

######################################################################################

###########################################################
# Sony PlayStation
###########################################################
sony_playstation = {}
sony_playstation[key_supercategory] = "Roms"
sony_playstation[key_category] = "Sony"
sony_playstation[key_subcategory] = "Sony PlayStation"
sony_playstation[key_transforms] = []
sony_playstation[key_addons] = []
sony_playstation[key_launcher] = [launch_type_file]
platforms["Sony PlayStation"] = sony_playstation

###########################################################
# Sony PlayStation 2
###########################################################
sony_playstation_2 = {}
sony_playstation_2[key_supercategory] = "Roms"
sony_playstation_2[key_category] = "Sony"
sony_playstation_2[key_subcategory] = "Sony PlayStation 2"
sony_playstation_2[key_transforms] = []
sony_playstation_2[key_addons] = []
sony_playstation_2[key_launcher] = [launch_type_file]
platforms["Sony PlayStation 2"] = sony_playstation_2

###########################################################
# Sony PlayStation 3
###########################################################
sony_playstation_3 = {}
sony_playstation_3[key_supercategory] = "Roms"
sony_playstation_3[key_category] = "Sony"
sony_playstation_3[key_subcategory] = "Sony PlayStation 3"
sony_playstation_3[key_transforms] = [transform_type_chd_to_iso, transform_type_iso_to_raw_ps3]
sony_playstation_3[key_addons] = [addon_type_dlc, addon_type_updates]
sony_playstation_3[key_launcher] = [launch_type_file]
platforms["Sony PlayStation 3"] = sony_playstation_3

###########################################################
# Sony PlayStation 4
###########################################################
sony_playstation_4 = {}
sony_playstation_4[key_supercategory] = "Roms"
sony_playstation_4[key_category] = "Sony"
sony_playstation_4[key_subcategory] = "Sony PlayStation 4"
sony_playstation_4[key_transforms] = []
sony_playstation_4[key_addons] = [addon_type_dlc, addon_type_updates]
sony_playstation_4[key_launcher] = [launch_type_none]
platforms["Sony PlayStation 4"] = sony_playstation_4

###########################################################
# Sony PlayStation Network - PlayStation 3
###########################################################
sony_playstation_network_ps3 = {}
sony_playstation_network_ps3[key_supercategory] = "Roms"
sony_playstation_network_ps3[key_category] = "Sony"
sony_playstation_network_ps3[key_subcategory] = "Sony PlayStation Network - PlayStation 3"
sony_playstation_network_ps3[key_transforms] = [transform_type_pkg_to_raw_ps3]
sony_playstation_network_ps3[key_addons] = [addon_type_dlc, addon_type_updates]
sony_playstation_network_ps3[key_launcher] = [launch_type_file]
platforms["Sony PlayStation Network - PlayStation 3"] = sony_playstation_network_ps3

###########################################################
# Sony PlayStation Network - PlayStation 4
###########################################################
sony_playstation_network_ps4 = {}
sony_playstation_network_ps4[key_supercategory] = "Roms"
sony_playstation_network_ps4[key_category] = "Sony"
sony_playstation_network_ps4[key_subcategory] = "Sony PlayStation Network - PlayStation 4"
sony_playstation_network_ps4[key_transforms] = []
sony_playstation_network_ps4[key_addons] = [addon_type_dlc, addon_type_updates]
sony_playstation_network_ps4[key_launcher] = [launch_type_none]
platforms["Sony PlayStation Network - PlayStation 4"] = sony_playstation_network_ps4

###########################################################
# Sony PlayStation Network - PlayStation Portable
###########################################################
sony_playstation_network_psp = {}
sony_playstation_network_psp[key_supercategory] = "Roms"
sony_playstation_network_psp[key_category] = "Sony"
sony_playstation_network_psp[key_subcategory] = "Sony PlayStation Network - PlayStation Portable"
sony_playstation_network_psp[key_transforms] = []
sony_playstation_network_psp[key_addons] = [addon_type_dlc, addon_type_updates]
sony_playstation_network_psp[key_launcher] = [launch_type_file]
platforms["Sony PlayStation Network - PlayStation Portable"] = sony_playstation_network_psp

###########################################################
# Sony PlayStation Network - PlayStation Portable Minis
###########################################################
sony_playstation_network_pspm = {}
sony_playstation_network_pspm[key_supercategory] = "Roms"
sony_playstation_network_pspm[key_category] = "Sony"
sony_playstation_network_pspm[key_subcategory] = "Sony PlayStation Network - PlayStation Portable Minis"
sony_playstation_network_pspm[key_transforms] = []
sony_playstation_network_pspm[key_addons] = []
sony_playstation_network_pspm[key_launcher] = [launch_type_file]
platforms["Sony PlayStation Network - PlayStation Portable Minis"] = sony_playstation_network_pspm

###########################################################
# Sony PlayStation Network - PlayStation Vita
###########################################################
sony_playstation_network_psv = {}
sony_playstation_network_psv[key_supercategory] = "Roms"
sony_playstation_network_psv[key_category] = "Sony"
sony_playstation_network_psv[key_subcategory] = "Sony PlayStation Network - PlayStation Vita"
sony_playstation_network_psv[key_transforms] = [transform_type_pkg_to_raw_psv]
sony_playstation_network_psv[key_addons] = [addon_type_dlc, addon_type_updates]
sony_playstation_network_psv[key_launcher] = [launch_type_name]
platforms["Sony PlayStation Network - PlayStation Vita"] = sony_playstation_network_psv

###########################################################
# Sony PlayStation Portable
###########################################################
sony_playstation_portable = {}
sony_playstation_portable[key_supercategory] = "Roms"
sony_playstation_portable[key_category] = "Sony"
sony_playstation_portable[key_subcategory] = "Sony PlayStation Portable"
sony_playstation_portable[key_transforms] = []
sony_playstation_portable[key_addons] = [addon_type_dlc, addon_type_updates]
sony_playstation_portable[key_launcher] = [launch_type_file]
platforms["Sony PlayStation Portable"] = sony_playstation_portable

###########################################################
# Sony PlayStation Portable Video
###########################################################
sony_playstation_portable_video = {}
sony_playstation_portable_video[key_supercategory] = "Roms"
sony_playstation_portable_video[key_category] = "Sony"
sony_playstation_portable_video[key_subcategory] = "Sony PlayStation Portable Video"
sony_playstation_portable_video[key_transforms] = []
sony_playstation_portable_video[key_addons] = []
sony_playstation_portable_video[key_launcher] = [launch_type_none]
platforms["Sony PlayStation Portable Video"] = sony_playstation_portable_video

###########################################################
# Sony PlayStation Vita
###########################################################
sony_playstation_vita = {}
sony_playstation_vita[key_supercategory] = "Roms"
sony_playstation_vita[key_category] = "Sony"
sony_playstation_vita[key_subcategory] = "Sony PlayStation Vita"
sony_playstation_vita[key_transforms] = []
sony_playstation_vita[key_addons] = [addon_type_dlc, addon_type_updates]
sony_playstation_vita[key_launcher] = [launch_type_name]
platforms["Sony PlayStation Vita"] = sony_playstation_vita
