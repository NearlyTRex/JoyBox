# Imports
import os
import sys

# Supercategories
game_supercategory_roms = "Roms"
game_supercategory_dlc = "DLC"
game_supercategory_updates = "Updates"
game_supercategory_saves = "Saves"
game_supercategory_setup = "Setup"
game_supercategory_installs = "Installs"
game_supercategories = [
    game_supercategory_roms,
    game_supercategory_dlc,
    game_supercategory_updates,
    game_supercategory_saves,
    game_supercategory_setup,
    game_supercategory_installs
]

# Categories
game_category_computer = "Computer"
game_category_microsoft = "Microsoft"
game_category_nintendo = "Nintendo"
game_category_other = "Other"
game_category_sony = "Sony"
game_categories = [
    game_category_computer,
    game_category_microsoft,
    game_category_nintendo,
    game_category_other,
    game_category_sony
]

# Subcategories - Computer
game_subcategory_amazon_games = "Amazon Games"
game_subcategory_disc = "Disc"
game_subcategory_epic_games = "Epic Games"
game_subcategory_gog = "GOG"
game_subcategory_humble_bundle = "Humble Bundle"
game_subcategory_itchio = "Itchio"
game_subcategory_puppet_combo = "Puppet Combo"
game_subcategory_red_candle = "Red Candle"
game_subcategory_square_enix = "Square Enix"
game_subcategory_steam = "Steam"
game_subcategory_zoom = "Zoom"
game_subcategories_computer = [
    game_subcategory_amazon_games,
    game_subcategory_disc,
    game_subcategory_epic_games,
    game_subcategory_gog,
    game_subcategory_humble_bundle,
    game_subcategory_itchio,
    game_subcategory_puppet_combo,
    game_subcategory_red_candle,
    game_subcategory_square_enix,
    game_subcategory_steam,
    game_subcategory_zoom
]

# Subcategories - Microsoft
game_subcategory_microsoft_msx = "Microsoft MSX"
game_subcategory_microsoft_xbox = "Microsoft Xbox"
game_subcategory_microsoft_xbox_360 = "Microsoft Xbox 360"
game_subcategory_microsoft_xbox_360_god = "Microsoft Xbox 360 GOD"
game_subcategory_microsoft_xbox_360_xbla = "Microsoft Xbox 360 XBLA"
game_subcategory_microsoft_xbox_360_xig = "Microsoft Xbox 360 XIG"
game_subcategory_microsoft_xbox_one = "Microsoft Xbox One"
game_subcategory_microsoft_xbox_one_god = "Microsoft Xbox One GOD"
game_subcategories_microsoft = [
    game_subcategory_microsoft_msx,
    game_subcategory_microsoft_xbox,
    game_subcategory_microsoft_xbox_360,
    game_subcategory_microsoft_xbox_360_god,
    game_subcategory_microsoft_xbox_360_xbla,
    game_subcategory_microsoft_xbox_360_xig,
    game_subcategory_microsoft_xbox_one,
    game_subcategory_microsoft_xbox_one_god
]

# Subcategories - Nintendo
game_subcategory_nintendo_3ds = "Nintendo 3DS"
game_subcategory_nintendo_3ds_apps = "Nintendo 3DS Apps"
game_subcategory_nintendo_3ds_eshop = "Nintendo 3DS eShop"
game_subcategory_nintendo_64 = "Nintendo 64"
game_subcategory_nintendo_ds = "Nintendo DS"
game_subcategory_nintendo_dsi = "Nintendo DSi"
game_subcategory_nintendo_famicom = "Nintendo Famicom"
game_subcategory_nintendo_game_boy = "Nintendo Game Boy"
game_subcategory_nintendo_game_boy_advance = "Nintendo Game Boy Advance"
game_subcategory_nintendo_game_boy_advance_ereader = "Nintendo Game Boy Advance e-Reader"
game_subcategory_nintendo_game_boy_color = "Nintendo Game Boy Color"
game_subcategory_nintendo_gamecube = "Nintendo Gamecube"
game_subcategory_nintendo_nes = "Nintendo NES"
game_subcategory_nintendo_snes = "Nintendo SNES"
game_subcategory_nintendo_snes_msu1 = "Nintendo SNES MSU-1"
game_subcategory_nintendo_super_famicom = "Nintendo Super Famicom"
game_subcategory_nintendo_super_game_boy = "Nintendo Super Game Boy"
game_subcategory_nintendo_super_game_boy_color = "Nintendo Super Game Boy Color"
game_subcategory_nintendo_switch = "Nintendo Switch"
game_subcategory_nintendo_switch_eshop = "Nintendo Switch eShop"
game_subcategory_nintendo_virtual_boy = "Nintendo Virtual Boy"
game_subcategory_nintendo_wii = "Nintendo Wii"
game_subcategory_nintendo_wii_u = "Nintendo Wii U"
game_subcategory_nintendo_wii_u_eshop = "Nintendo Wii U eShop"
game_subcategories_nintendo = [
    game_subcategory_nintendo_3ds,
    game_subcategory_nintendo_3ds_apps,
    game_subcategory_nintendo_3ds_eshop,
    game_subcategory_nintendo_64,
    game_subcategory_nintendo_ds,
    game_subcategory_nintendo_dsi,
    game_subcategory_nintendo_famicom,
    game_subcategory_nintendo_game_boy,
    game_subcategory_nintendo_game_boy_advance,
    game_subcategory_nintendo_game_boy_advance_ereader,
    game_subcategory_nintendo_game_boy_color,
    game_subcategory_nintendo_gamecube,
    game_subcategory_nintendo_nes,
    game_subcategory_nintendo_snes,
    game_subcategory_nintendo_snes_msu1,
    game_subcategory_nintendo_super_famicom,
    game_subcategory_nintendo_super_game_boy,
    game_subcategory_nintendo_super_game_boy_color,
    game_subcategory_nintendo_switch,
    game_subcategory_nintendo_switch_eshop,
    game_subcategory_nintendo_virtual_boy,
    game_subcategory_nintendo_wii,
    game_subcategory_nintendo_wii_u,
    game_subcategory_nintendo_wii_u_eshop
]

# Subcategories - Other
game_subcategory_apple_ios = "Apple iOS"
game_subcategory_apple_macos_8 = "Apple MacOS 8"
game_subcategory_arcade = "Arcade"
game_subcategory_atari_800 = "Atari 800"
game_subcategory_atari_2600 = "Atari 2600"
game_subcategory_atari_5200 = "Atari 5200"
game_subcategory_atari_7800 = "Atari 7800"
game_subcategory_atari_jaguar = "Atari Jaguar"
game_subcategory_atari_jaguar_cd = "Atari Jaguar CD"
game_subcategory_atari_lynx = "Atari Lynx"
game_subcategory_bandai_wonderswan = "Bandai WonderSwan"
game_subcategory_bandai_wonderswan_color = "Bandai WonderSwan Color"
game_subcategory_coleco_colecovision = "Coleco ColecoVision"
game_subcategory_commodore_64 = "Commodore 64"
game_subcategory_commodore_amiga = "Commodore Amiga"
game_subcategory_google_android = "Google Android"
game_subcategory_magnavox_odyssey_2 = "Magnavox Odyssey 2"
game_subcategory_mattel_intellivision = "Mattel Intellivision"
game_subcategory_nec_supergrafx = "NEC SuperGrafx"
game_subcategory_nec_turbografx_pcengine_cd = "NEC TurboGrafx CD & PC-Engine CD"
game_subcategory_nec_turbografx_pcengine = "NEC TurboGrafx-16 & PC-Engine"
game_subcategory_nokia_ngage = "Nokia N-Gage"
game_subcategory_panasonic_3do = "Panasonic 3DO"
game_subcategory_philips_cdi = "Philips CDi"
game_subcategory_snk_neogeo_pocket_color = "SNK Neo Geo Pocket Color"
game_subcategory_sega_32x = "Sega 32X"
game_subcategory_sega_cd = "Sega CD"
game_subcategory_sega_cd_32x = "Sega CD 32X"
game_subcategory_sega_dreamcast = "Sega Dreamcast"
game_subcategory_sega_game_gear = "Sega Game Gear"
game_subcategory_sega_genesis = "Sega Genesis"
game_subcategory_sega_master_system = "Sega Master System"
game_subcategory_sega_saturn = "Sega Saturn"
game_subcategory_sinclair_zx_spectrum = "Sinclair ZX Spectrum"
game_subcategory_texas_instruments_ti994a = "Texas Instruments TI-99-4A"
game_subcategory_tiger_gamecom = "Tiger Game.com"
game_subcategories_other = [
    game_subcategory_apple_ios,
    game_subcategory_apple_macos_8,
    game_subcategory_arcade,
    game_subcategory_atari_800,
    game_subcategory_atari_2600,
    game_subcategory_atari_5200,
    game_subcategory_atari_7800,
    game_subcategory_atari_jaguar,
    game_subcategory_atari_jaguar_cd,
    game_subcategory_atari_lynx,
    game_subcategory_bandai_wonderswan,
    game_subcategory_bandai_wonderswan_color,
    game_subcategory_coleco_colecovision,
    game_subcategory_commodore_64,
    game_subcategory_commodore_amiga,
    game_subcategory_google_android,
    game_subcategory_magnavox_odyssey_2,
    game_subcategory_mattel_intellivision,
    game_subcategory_nec_supergrafx,
    game_subcategory_nec_turbografx_pcengine_cd,
    game_subcategory_nec_turbografx_pcengine,
    game_subcategory_nokia_ngage,
    game_subcategory_panasonic_3do,
    game_subcategory_philips_cdi,
    game_subcategory_snk_neogeo_pocket_color,
    game_subcategory_sega_32x,
    game_subcategory_sega_cd,
    game_subcategory_sega_cd_32x,
    game_subcategory_sega_dreamcast,
    game_subcategory_sega_game_gear,
    game_subcategory_sega_genesis,
    game_subcategory_sega_master_system,
    game_subcategory_sega_saturn,
    game_subcategory_sinclair_zx_spectrum,
    game_subcategory_texas_instruments_ti994a,
    game_subcategory_tiger_gamecom
]

# Subcategories - Sony
game_subcategory_sony_playstation = "Sony PlayStation"
game_subcategory_sony_playstation_2 = "Sony PlayStation 2"
game_subcategory_sony_playstation_3 = "Sony PlayStation 3"
game_subcategory_sony_playstation_4 = "Sony PlayStation 4"
game_subcategory_sony_playstation_network_ps3 = "Sony PlayStation Network - PlayStation 3"
game_subcategory_sony_playstation_network_ps4 = "Sony PlayStation Network - PlayStation 4"
game_subcategory_sony_playstation_network_psp = "Sony PlayStation Network - PlayStation Portable"
game_subcategory_sony_playstation_network_pspm = "Sony PlayStation Network - PlayStation Portable Minis"
game_subcategory_sony_playstation_network_psv = "Sony PlayStation Network - PlayStation Vita"
game_subcategory_sony_playstation_portable = "Sony PlayStation Portable"
game_subcategory_sony_playstation_portable_video = "Sony PlayStation Portable Video"
game_subcategory_sony_playstation_vita = "Sony PlayStation Vita"
game_subcategories_sony = [
    game_subcategory_sony_playstation,
    game_subcategory_sony_playstation_2,
    game_subcategory_sony_playstation_3,
    game_subcategory_sony_playstation_4,
    game_subcategory_sony_playstation_network_ps3,
    game_subcategory_sony_playstation_network_ps4,
    game_subcategory_sony_playstation_network_psp,
    game_subcategory_sony_playstation_network_pspm,
    game_subcategory_sony_playstation_network_psv,
    game_subcategory_sony_playstation_portable,
    game_subcategory_sony_playstation_portable_video,
    game_subcategory_sony_playstation_vita
]

# Subcategories
game_subcategories = {
    game_category_computer: game_subcategories_computer,
    game_category_microsoft: game_subcategories_microsoft,
    game_category_nintendo: game_subcategories_nintendo,
    game_category_other: game_subcategories_other,
    game_category_sony: game_subcategories_sony
}
game_subcategories_all = []
game_subcategories_all += game_subcategories_computer
game_subcategories_all += game_subcategories_microsoft
game_subcategories_all += game_subcategories_nintendo
game_subcategories_all += game_subcategories_other
game_subcategories_all += game_subcategories_sony
