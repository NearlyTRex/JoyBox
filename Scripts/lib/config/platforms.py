# Imports
import os
import sys

# Local imports
from . import categories
from . import keys
from . import types

# Platforms
platforms = {}

# Computer
class ComputerPlatform(types.EnumType):
    AMAZON_GAMES                        = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_AMAZON_GAMES.value)
    DISC                                = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_DISC.value)
    EPIC_GAMES                          = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_EPIC_GAMES.value)
    GOG                                 = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_GOG.value)
    HUMBLE_BUNDLE                       = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_HUMBLE_BUNDLE.value)
    ITCHIO                              = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_ITCHIO.value)
    LEGACY_GAMES                        = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_LEGACY_GAMES.value)
    PUPPET_COMBO                        = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_PUPPET_COMBO.value)
    RED_CANDLE                          = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_RED_CANDLE.value)
    SQUARE_ENIX                         = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_SQUARE_ENIX.value)
    STEAM                               = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_STEAM.value)
    ZOOM                                = (categories.Category.COMPUTER.value + " - " + categories.Subcategory.COMPUTER_ZOOM.value)

# Microsoft
class MicrosoftPlatform(types.EnumType):
    MICROSOFT_MSX                       = (categories.Subcategory.MICROSOFT_MSX.value)
    MICROSOFT_XBOX                      = (categories.Subcategory.MICROSOFT_XBOX.value)
    MICROSOFT_XBOX_360                  = (categories.Subcategory.MICROSOFT_XBOX_360.value)
    MICROSOFT_XBOX_360_GOD              = (categories.Subcategory.MICROSOFT_XBOX_360_GOD.value)
    MICROSOFT_XBOX_360_XBLA             = (categories.Subcategory.MICROSOFT_XBOX_360_XBLA.value)
    MICROSOFT_XBOX_360_XIG              = (categories.Subcategory.MICROSOFT_XBOX_360_XIG.value)
    MICROSOFT_XBOX_ONE                  = (categories.Subcategory.MICROSOFT_XBOX_ONE.value)
    MICROSOFT_XBOX_ONE_GOD              = (categories.Subcategory.MICROSOFT_XBOX_ONE_GOD.value)

# Nintendo
class NintendoPlatform(types.EnumType):
    NINTENDO_3DS                        = (categories.Subcategory.NINTENDO_3DS.value)
    NINTENDO_3DS_APPS                   = (categories.Subcategory.NINTENDO_3DS_APPS.value)
    NINTENDO_3DS_ESHOP                  = (categories.Subcategory.NINTENDO_3DS_ESHOP.value)
    NINTENDO_64                         = (categories.Subcategory.NINTENDO_64.value)
    NINTENDO_AMIIBO                     = (categories.Subcategory.NINTENDO_AMIIBO.value)
    NINTENDO_DS                         = (categories.Subcategory.NINTENDO_DS.value)
    NINTENDO_DSI                        = (categories.Subcategory.NINTENDO_DSI.value)
    NINTENDO_FAMICOM                    = (categories.Subcategory.NINTENDO_FAMICOM.value)
    NINTENDO_GAME_BOY                   = (categories.Subcategory.NINTENDO_GAME_BOY.value)
    NINTENDO_GAME_BOY_ADVANCE           = (categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE.value)
    NINTENDO_GAME_BOY_ADVANCE_EREADER   = (categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE_EREADER.value)
    NINTENDO_GAME_BOY_COLOR             = (categories.Subcategory.NINTENDO_GAME_BOY_COLOR.value)
    NINTENDO_GAMECUBE                   = (categories.Subcategory.NINTENDO_GAMECUBE.value)
    NINTENDO_NES                        = (categories.Subcategory.NINTENDO_NES.value)
    NINTENDO_SNES                       = (categories.Subcategory.NINTENDO_SNES.value)
    NINTENDO_SNES_MSU1                  = (categories.Subcategory.NINTENDO_SNES_MSU1.value)
    NINTENDO_SUPER_FAMICOM              = (categories.Subcategory.NINTENDO_SUPER_FAMICOM.value)
    NINTENDO_SUPER_GAME_BOY             = (categories.Subcategory.NINTENDO_SUPER_GAME_BOY.value)
    NINTENDO_SUPER_GAME_BOY_COLOR       = (categories.Subcategory.NINTENDO_SUPER_GAME_BOY_COLOR.value)
    NINTENDO_SWITCH                     = (categories.Subcategory.NINTENDO_SWITCH.value)
    NINTENDO_SWITCH_ESHOP               = (categories.Subcategory.NINTENDO_SWITCH_ESHOP.value)
    NINTENDO_VIRTUAL_BOY                = (categories.Subcategory.NINTENDO_VIRTUAL_BOY.value)
    NINTENDO_WII                        = (categories.Subcategory.NINTENDO_WII.value)
    NINTENDO_WII_U                      = (categories.Subcategory.NINTENDO_WII_U.value)
    NINTENDO_WII_U_ESHOP                = (categories.Subcategory.NINTENDO_WII_U_ESHOP.value)
    NINTENDO_WIIWARE                    = (categories.Subcategory.NINTENDO_WIIWARE.value)

# Other
class OtherPlatform(types.EnumType):
    APPLE_IOS                           = (categories.Subcategory.OTHER_APPLE_IOS.value)
    APPLE_MACOS_8                       = (categories.Subcategory.OTHER_APPLE_MACOS_8.value)
    ARCADE                              = (categories.Subcategory.OTHER_ARCADE.value)
    ATARI_800                           = (categories.Subcategory.OTHER_ATARI_800.value)
    ATARI_2600                          = (categories.Subcategory.OTHER_ATARI_2600.value)
    ATARI_5200                          = (categories.Subcategory.OTHER_ATARI_5200.value)
    ATARI_7800                          = (categories.Subcategory.OTHER_ATARI_7800.value)
    ATARI_JAGUAR                        = (categories.Subcategory.OTHER_ATARI_JAGUAR.value)
    ATARI_JAGUAR_CD                     = (categories.Subcategory.OTHER_ATARI_JAGUAR_CD.value)
    ATARI_LYNX                          = (categories.Subcategory.OTHER_ATARI_LYNX.value)
    BANDAI_WONDERSWAN                   = (categories.Subcategory.OTHER_BANDAI_WONDERSWAN.value)
    BANDAI_WONDERSWAN_COLOR             = (categories.Subcategory.OTHER_BANDAI_WONDERSWAN_COLOR.value)
    COLECO_COLECOVISION                 = (categories.Subcategory.OTHER_COLECO_COLECOVISION.value)
    COMMODORE_64                        = (categories.Subcategory.OTHER_COMMODORE_64.value)
    COMMODORE_AMIGA                     = (categories.Subcategory.OTHER_COMMODORE_AMIGA.value)
    GOOGLE_ANDROID                      = (categories.Subcategory.OTHER_GOOGLE_ANDROID.value)
    MAGNAVOX_ODYSSEY_2                  = (categories.Subcategory.OTHER_MAGNAVOX_ODYSSEY_2.value)
    MATTEL_INTELLIVISION                = (categories.Subcategory.OTHER_MATTEL_INTELLIVISION.value)
    NEC_PCENGINE                        = (categories.Subcategory.OTHER_NEC_PCENGINE.value)
    NEC_PCENGINE_CD                     = (categories.Subcategory.OTHER_NEC_PCENGINE_CD.value)
    NEC_SUPERGRAFX                      = (categories.Subcategory.OTHER_NEC_SUPERGRAFX.value)
    NEC_TURBOGRAFX_16                   = (categories.Subcategory.OTHER_NEC_TURBOGRAFX_16.value)
    NEC_TURBOGRAFX_CD                   = (categories.Subcategory.OTHER_NEC_TURBOGRAFX_CD.value)
    NOKIA_NGAGE                         = (categories.Subcategory.OTHER_NOKIA_NGAGE.value)
    PANASONIC_3DO                       = (categories.Subcategory.OTHER_PANASONIC_3DO.value)
    PHILIPS_CDI                         = (categories.Subcategory.OTHER_PHILIPS_CDI.value)
    SNK_NEOGEO_POCKET_COLOR             = (categories.Subcategory.OTHER_SNK_NEOGEO_POCKET_COLOR.value)
    SEGA_32X                            = (categories.Subcategory.OTHER_SEGA_32X.value)
    SEGA_CD                             = (categories.Subcategory.OTHER_SEGA_CD.value)
    SEGA_CD_32X                         = (categories.Subcategory.OTHER_SEGA_CD_32X.value)
    SEGA_DREAMCAST                      = (categories.Subcategory.OTHER_SEGA_DREAMCAST.value)
    SEGA_GAME_GEAR                      = (categories.Subcategory.OTHER_SEGA_GAME_GEAR.value)
    SEGA_GENESIS                        = (categories.Subcategory.OTHER_SEGA_GENESIS.value)
    SEGA_MASTER_SYSTEM                  = (categories.Subcategory.OTHER_SEGA_MASTER_SYSTEM.value)
    SEGA_SATURN                         = (categories.Subcategory.OTHER_SEGA_SATURN.value)
    SINCLAIR_ZX_SPECTRUM                = (categories.Subcategory.OTHER_SINCLAIR_ZX_SPECTRUM.value)
    TEXAS_INSTRUMENTS_TI994A            = (categories.Subcategory.OTHER_TEXAS_INSTRUMENTS_TI994A.value)
    TIGER_GAMECOM                       = (categories.Subcategory.OTHER_TIGER_GAMECOM.value)

# Sony
class SonyPlatform(types.EnumType):
    SONY_PLAYSTATION                    = (categories.Subcategory.SONY_PLAYSTATION.value)
    SONY_PLAYSTATION_2                  = (categories.Subcategory.SONY_PLAYSTATION_2.value)
    SONY_PLAYSTATION_3                  = (categories.Subcategory.SONY_PLAYSTATION_3.value)
    SONY_PLAYSTATION_4                  = (categories.Subcategory.SONY_PLAYSTATION_4.value)
    SONY_PLAYSTATION_NETWORK_PS3        = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS3.value)
    SONY_PLAYSTATION_NETWORK_PS4        = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS4.value)
    SONY_PLAYSTATION_NETWORK_PSP        = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSP.value)
    SONY_PLAYSTATION_NETWORK_PSPM       = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSPM.value)
    SONY_PLAYSTATION_NETWORK_PSV        = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSV.value)
    SONY_PLAYSTATION_PORTABLE           = (categories.Subcategory.SONY_PLAYSTATION_PORTABLE.value)
    SONY_PLAYSTATION_PORTABLE_VIDEO     = (categories.Subcategory.SONY_PLAYSTATION_PORTABLE_VIDEO.value)
    SONY_PLAYSTATION_VITA               = (categories.Subcategory.SONY_PLAYSTATION_VITA.value)

# Transform platforms
TransformPlatforms = [

    # Computer
    ComputerPlatform.AMAZON_GAMES,
    ComputerPlatform.DISC,
    ComputerPlatform.EPIC_GAMES,
    ComputerPlatform.GOG,
    ComputerPlatform.HUMBLE_BUNDLE,
    ComputerPlatform.ITCHIO,
    ComputerPlatform.LEGACY_GAMES,
    ComputerPlatform.PUPPET_COMBO,
    ComputerPlatform.RED_CANDLE,
    ComputerPlatform.SQUARE_ENIX,
    ComputerPlatform.STEAM,
    ComputerPlatform.ZOOM,

    # Microsoft
    MicrosoftPlatform.MICROSOFT_XBOX,
    MicrosoftPlatform.MICROSOFT_XBOX_360,

    # Sony
    SonyPlatform.SONY_PLAYSTATION_3,
    SonyPlatform.SONY_PLAYSTATION_NETWORK_PS3,
    SonyPlatform.SONY_PLAYSTATION_NETWORK_PSV
]

# Letter platforms
LetterPlatforms = [

    # Computer
    ComputerPlatform.AMAZON_GAMES,
    ComputerPlatform.DISC,
    ComputerPlatform.EPIC_GAMES,
    ComputerPlatform.GOG,
    ComputerPlatform.HUMBLE_BUNDLE,
    ComputerPlatform.ITCHIO,
    ComputerPlatform.LEGACY_GAMES,
    ComputerPlatform.PUPPET_COMBO,
    ComputerPlatform.RED_CANDLE,
    ComputerPlatform.SQUARE_ENIX,
    ComputerPlatform.STEAM,
    ComputerPlatform.ZOOM
]

######################################################################################

###########################################################
# Computer - Amazon Games
###########################################################
computer_amazon_games = {}
computer_amazon_games[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_amazon_games[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_amazon_games[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_AMAZON_GAMES.value
computer_amazon_games[keys.platform_key_addons] = []
computer_amazon_games[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
    keys.json_key_store_appid,
    keys.json_key_store_appname,
    keys.json_key_store_appurl,
    keys.json_key_store_branchid,
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
computer_amazon_games[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.AMAZON_GAMES.value] = computer_amazon_games

###########################################################
# Computer - Disc
###########################################################
computer_disc = {}
computer_disc[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_disc[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_disc[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_DISC.value
computer_disc[keys.platform_key_addons] = []
computer_disc[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
computer_disc[keys.platform_key_autofill_json] = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_transform_file
]
computer_disc[keys.platform_key_fillonce_json] = []
computer_disc[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.DISC.value] = computer_disc

###########################################################
# Computer - Epic Games
###########################################################
computer_epic_games = {}
computer_epic_games[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_epic_games[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_epic_games[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_EPIC_GAMES.value
computer_epic_games[keys.platform_key_addons] = []
computer_epic_games[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
    keys.json_key_store_appid,
    keys.json_key_store_appname,
    keys.json_key_store_appurl,
    keys.json_key_store_branchid
]
computer_epic_games[keys.platform_key_merge_json] = [
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
platforms[ComputerPlatform.EPIC_GAMES.value] = computer_epic_games

###########################################################
# Computer - GOG
###########################################################
computer_gog = {}
computer_gog[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_gog[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_gog[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_GOG.value
computer_gog[keys.platform_key_addons] = []
computer_gog[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
    keys.json_key_store_appid,
    keys.json_key_store_appname,
    keys.json_key_store_appurl,
    keys.json_key_store_branchid,
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
computer_gog[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.GOG.value] = computer_gog

###########################################################
# Computer - Humble Bundle
###########################################################
computer_humble_bundle = {}
computer_humble_bundle[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_humble_bundle[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_humble_bundle[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_HUMBLE_BUNDLE.value
computer_humble_bundle[keys.platform_key_addons] = []
computer_humble_bundle[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
computer_humble_bundle[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.HUMBLE_BUNDLE.value] = computer_humble_bundle

###########################################################
# Computer - Itchio
###########################################################
computer_itchio = {}
computer_itchio[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_itchio[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_itchio[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_ITCHIO.value
computer_itchio[keys.platform_key_addons] = []
computer_itchio[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
computer_itchio[keys.platform_key_autofill_json] = [
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
computer_itchio[keys.platform_key_fillonce_json] = [
    keys.json_key_itchio,
    keys.json_key_store_appid,
    keys.json_key_store_appname,
    keys.json_key_store_appurl,
    keys.json_key_store_branchid,
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
computer_itchio[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.ITCHIO.value] = computer_itchio

###########################################################
# Computer - Legacy Games
###########################################################
computer_legacy_games = {}
computer_legacy_games[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_legacy_games[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_legacy_games[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_LEGACY_GAMES.value
computer_legacy_games[keys.platform_key_addons] = []
computer_legacy_games[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
computer_legacy_games[keys.platform_key_autofill_json] = [
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
computer_legacy_games[keys.platform_key_fillonce_json] = [
    keys.json_key_legacy,
    keys.json_key_store_appid,
    keys.json_key_store_appname,
    keys.json_key_store_appurl,
    keys.json_key_store_branchid
]
computer_legacy_games[keys.platform_key_merge_json] = [
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
platforms[ComputerPlatform.LEGACY_GAMES.value] = computer_legacy_games

###########################################################
# Computer - Puppet Combo
###########################################################
computer_puppet_combo = {}
computer_puppet_combo[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_puppet_combo[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_puppet_combo[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_PUPPET_COMBO.value
computer_puppet_combo[keys.platform_key_addons] = []
computer_puppet_combo[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
computer_puppet_combo[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.PUPPET_COMBO.value] = computer_puppet_combo

###########################################################
# Computer - Red Candle
###########################################################
computer_red_candle = {}
computer_red_candle[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_red_candle[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_red_candle[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_RED_CANDLE.value
computer_red_candle[keys.platform_key_addons] = []
computer_red_candle[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
computer_red_candle[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.RED_CANDLE.value] = computer_red_candle

###########################################################
# Computer - Square Enix
###########################################################
computer_square_enix = {}
computer_square_enix[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_square_enix[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_square_enix[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_SQUARE_ENIX.value
computer_square_enix[keys.platform_key_addons] = []
computer_square_enix[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
computer_square_enix[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.SQUARE_ENIX.value] = computer_square_enix

###########################################################
# Computer - Steam
###########################################################
computer_steam = {}
computer_steam[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_steam[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_steam[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_STEAM.value
computer_steam[keys.platform_key_addons] = []
computer_steam[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
    keys.json_key_store_appid,
    keys.json_key_store_appname,
    keys.json_key_store_appurl,
    keys.json_key_store_branchid
]
computer_steam[keys.platform_key_merge_json] = [
    keys.json_key_store_paths,
    keys.json_key_store_keys
]
platforms[ComputerPlatform.STEAM.value] = computer_steam

###########################################################
# Computer - Zoom
###########################################################
computer_zoom = {}
computer_zoom[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
computer_zoom[keys.platform_key_category] = categories.Category.COMPUTER.value
computer_zoom[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_ZOOM.value
computer_zoom[keys.platform_key_addons] = []
computer_zoom[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
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
computer_zoom[keys.platform_key_merge_json] = []
platforms[ComputerPlatform.ZOOM.value] = computer_zoom

######################################################################################

###########################################################
# Microsoft MSX
###########################################################
microsoft_msx = {}
microsoft_msx[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
microsoft_msx[keys.platform_key_category] = categories.Category.MICROSOFT.value
microsoft_msx[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_MSX.value
microsoft_msx[keys.platform_key_addons] = []
microsoft_msx[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
microsoft_msx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
microsoft_msx[keys.platform_key_fillonce_json] = []
microsoft_msx[keys.platform_key_merge_json] = []
platforms[MicrosoftPlatform.MICROSOFT_MSX.value] = microsoft_msx

###########################################################
# Microsoft Xbox
###########################################################
microsoft_xbox = {}
microsoft_xbox[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
microsoft_xbox[keys.platform_key_category] = categories.Category.MICROSOFT.value
microsoft_xbox[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX.value
microsoft_xbox[keys.platform_key_addons] = []
microsoft_xbox[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
microsoft_xbox[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
microsoft_xbox[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox[keys.platform_key_merge_json] = []
platforms[MicrosoftPlatform.MICROSOFT_XBOX.value] = microsoft_xbox

###########################################################
# Microsoft Xbox 360
###########################################################
microsoft_xbox_360 = {}
microsoft_xbox_360[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
microsoft_xbox_360[keys.platform_key_category] = categories.Category.MICROSOFT.value
microsoft_xbox_360[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_360.value
microsoft_xbox_360[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
microsoft_xbox_360[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
microsoft_xbox_360[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
microsoft_xbox_360[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox_360[keys.platform_key_merge_json] = []
platforms[MicrosoftPlatform.MICROSOFT_XBOX_360.value] = microsoft_xbox_360

###########################################################
# Microsoft Xbox 360 GOD
###########################################################
microsoft_xbox_360_god = {}
microsoft_xbox_360_god[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
microsoft_xbox_360_god[keys.platform_key_category] = categories.Category.MICROSOFT.value
microsoft_xbox_360_god[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_360_GOD.value
microsoft_xbox_360_god[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
microsoft_xbox_360_god[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
microsoft_xbox_360_god[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_god[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox_360_god[keys.platform_key_merge_json] = []
platforms[MicrosoftPlatform.MICROSOFT_XBOX_360_GOD.value] = microsoft_xbox_360_god

###########################################################
# Microsoft Xbox 360 XBLA
###########################################################
microsoft_xbox_360_xbla = {}
microsoft_xbox_360_xbla[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
microsoft_xbox_360_xbla[keys.platform_key_category] = categories.Category.MICROSOFT.value
microsoft_xbox_360_xbla[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_360_XBLA.value
microsoft_xbox_360_xbla[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
microsoft_xbox_360_xbla[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
microsoft_xbox_360_xbla[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_xbla[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox_360_xbla[keys.platform_key_merge_json] = []
platforms[MicrosoftPlatform.MICROSOFT_XBOX_360_XBLA.value] = microsoft_xbox_360_xbla

###########################################################
# Microsoft Xbox 360 XIG
###########################################################
microsoft_xbox_360_xig = {}
microsoft_xbox_360_xig[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
microsoft_xbox_360_xig[keys.platform_key_category] = categories.Category.MICROSOFT.value
microsoft_xbox_360_xig[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_360_XIG.value
microsoft_xbox_360_xig[keys.platform_key_addons] = []
microsoft_xbox_360_xig[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
microsoft_xbox_360_xig[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_xig[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox_360_xig[keys.platform_key_merge_json] = []
platforms[MicrosoftPlatform.MICROSOFT_XBOX_360_XIG.value] = microsoft_xbox_360_xig

###########################################################
# Microsoft Xbox One
###########################################################
microsoft_xbox_one = {}
microsoft_xbox_one[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
microsoft_xbox_one[keys.platform_key_category] = categories.Category.MICROSOFT.value
microsoft_xbox_one[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_ONE.value
microsoft_xbox_one[keys.platform_key_addons] = []
microsoft_xbox_one[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER.value]
microsoft_xbox_one[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_one[keys.platform_key_fillonce_json] = []
microsoft_xbox_one[keys.platform_key_merge_json] = []
platforms[MicrosoftPlatform.MICROSOFT_XBOX_ONE.value] = microsoft_xbox_one

###########################################################
# Microsoft Xbox One GOD
###########################################################
microsoft_xbox_one_god = {}
microsoft_xbox_one_god[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
microsoft_xbox_one_god[keys.platform_key_category] = categories.Category.MICROSOFT.value
microsoft_xbox_one_god[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_ONE_GOD.value
microsoft_xbox_one_god[keys.platform_key_addons] = []
microsoft_xbox_one_god[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER.value]
microsoft_xbox_one_god[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_one_god[keys.platform_key_fillonce_json] = []
microsoft_xbox_one_god[keys.platform_key_merge_json] = []
platforms[MicrosoftPlatform.MICROSOFT_XBOX_ONE_GOD.value] = microsoft_xbox_one_god

######################################################################################

###########################################################
# Nintendo 3DS
###########################################################
nintendo_3ds = {}
nintendo_3ds[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_3ds[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_3ds[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_3DS.value
nintendo_3ds[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
nintendo_3ds[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_3ds[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_3ds[keys.platform_key_fillonce_json] = []
nintendo_3ds[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_3DS.value] = nintendo_3ds

###########################################################
# Nintendo 3DS Apps
###########################################################
nintendo_3ds_apps = {}
nintendo_3ds_apps[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_3ds_apps[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_3ds_apps[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_3DS_APPS.value
nintendo_3ds_apps[keys.platform_key_addons] = []
nintendo_3ds_apps[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER.value]
nintendo_3ds_apps[keys.platform_key_autofill_json] = [keys.json_key_files]
nintendo_3ds_apps[keys.platform_key_fillonce_json] = []
nintendo_3ds_apps[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_3DS_APPS.value] = nintendo_3ds_apps

###########################################################
# Nintendo 3DS eShop
###########################################################
nintendo_3ds_eshop = {}
nintendo_3ds_eshop[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_3ds_eshop[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_3ds_eshop[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_3DS_ESHOP.value
nintendo_3ds_eshop[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
nintendo_3ds_eshop[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_3ds_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_3ds_eshop[keys.platform_key_fillonce_json] = []
nintendo_3ds_eshop[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_3DS_ESHOP.value] = nintendo_3ds_eshop

###########################################################
# Nintendo 64
###########################################################
nintendo_64 = {}
nintendo_64[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_64[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_64[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_64.value
nintendo_64[keys.platform_key_addons] = []
nintendo_64[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_64[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_64[keys.platform_key_fillonce_json] = []
nintendo_64[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_64.value] = nintendo_64

###########################################################
# Nintendo DS
###########################################################
nintendo_ds = {}
nintendo_ds[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_ds[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_ds[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_DS.value
nintendo_ds[keys.platform_key_addons] = []
nintendo_ds[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_ds[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_ds[keys.platform_key_fillonce_json] = []
nintendo_ds[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_DS.value] = nintendo_ds

###########################################################
# Nintendo DSi
###########################################################
nintendo_dsi = {}
nintendo_dsi[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_dsi[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_dsi[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_DSI.value
nintendo_dsi[keys.platform_key_addons] = []
nintendo_dsi[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_dsi[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_dsi[keys.platform_key_fillonce_json] = []
nintendo_dsi[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_DSI.value] = nintendo_dsi

###########################################################
# Nintendo Famicom
###########################################################
nintendo_famicom = {}
nintendo_famicom[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_famicom[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_famicom[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_FAMICOM.value
nintendo_famicom[keys.platform_key_addons] = []
nintendo_famicom[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_famicom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_famicom[keys.platform_key_fillonce_json] = []
nintendo_famicom[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_FAMICOM.value] = nintendo_famicom

###########################################################
# Nintendo Game Boy
###########################################################
nintendo_game_boy = {}
nintendo_game_boy[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_game_boy[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_game_boy[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAME_BOY.value
nintendo_game_boy[keys.platform_key_addons] = []
nintendo_game_boy[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_game_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy[keys.platform_key_fillonce_json] = []
nintendo_game_boy[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_GAME_BOY.value] = nintendo_game_boy

###########################################################
# Nintendo Game Boy Advance
###########################################################
nintendo_game_boy_advance = {}
nintendo_game_boy_advance[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_game_boy_advance[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_game_boy_advance[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE.value
nintendo_game_boy_advance[keys.platform_key_addons] = []
nintendo_game_boy_advance[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_game_boy_advance[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_advance[keys.platform_key_fillonce_json] = []
nintendo_game_boy_advance[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_GAME_BOY_ADVANCE.value] = nintendo_game_boy_advance

###########################################################
# Nintendo Game Boy Advance e-Reader
###########################################################
nintendo_game_boy_advance_ereader = {}
nintendo_game_boy_advance_ereader[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_game_boy_advance_ereader[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_game_boy_advance_ereader[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE_EREADER.value
nintendo_game_boy_advance_ereader[keys.platform_key_addons] = []
nintendo_game_boy_advance_ereader[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_game_boy_advance_ereader[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_advance_ereader[keys.platform_key_fillonce_json] = []
nintendo_game_boy_advance_ereader[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_GAME_BOY_ADVANCE_EREADER.value] = nintendo_game_boy_advance_ereader

###########################################################
# Nintendo Game Boy Color
###########################################################
nintendo_game_boy_color = {}
nintendo_game_boy_color[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_game_boy_color[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_game_boy_color[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAME_BOY_COLOR.value
nintendo_game_boy_color[keys.platform_key_addons] = []
nintendo_game_boy_color[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_game_boy_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_color[keys.platform_key_fillonce_json] = []
nintendo_game_boy_color[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_GAME_BOY_COLOR.value] = nintendo_game_boy_color

###########################################################
# Nintendo Gamecube
###########################################################
nintendo_gamecube = {}
nintendo_gamecube[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_gamecube[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_gamecube[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAMECUBE.value
nintendo_gamecube[keys.platform_key_addons] = []
nintendo_gamecube[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_gamecube[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_gamecube[keys.platform_key_fillonce_json] = []
nintendo_gamecube[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_GAMECUBE.value] = nintendo_gamecube

###########################################################
# Nintendo NES
###########################################################
nintendo_nes = {}
nintendo_nes[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_nes[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_nes[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_NES.value
nintendo_nes[keys.platform_key_addons] = []
nintendo_nes[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_nes[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_nes[keys.platform_key_fillonce_json] = []
nintendo_nes[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_NES.value] = nintendo_nes

###########################################################
# Nintendo SNES
###########################################################
nintendo_snes = {}
nintendo_snes[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_snes[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_snes[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SNES.value
nintendo_snes[keys.platform_key_addons] = []
nintendo_snes[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_snes[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_snes[keys.platform_key_fillonce_json] = []
nintendo_snes[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_SNES.value] = nintendo_snes

###########################################################
# Nintendo SNES MSU-1
###########################################################
nintendo_snes_msu1 = {}
nintendo_snes_msu1[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_snes_msu1[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_snes_msu1[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SNES_MSU1.value
nintendo_snes_msu1[keys.platform_key_addons] = []
nintendo_snes_msu1[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_snes_msu1[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_snes_msu1[keys.platform_key_fillonce_json] = []
nintendo_snes_msu1[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_SNES_MSU1.value] = nintendo_snes_msu1

###########################################################
# Nintendo Super Famicom
###########################################################
nintendo_super_famicom = {}
nintendo_super_famicom[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_super_famicom[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_super_famicom[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SUPER_FAMICOM.value
nintendo_super_famicom[keys.platform_key_addons] = []
nintendo_super_famicom[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_super_famicom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_famicom[keys.platform_key_fillonce_json] = []
nintendo_super_famicom[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_SUPER_FAMICOM.value] = nintendo_super_famicom

###########################################################
# Nintendo Super Game Boy
###########################################################
nintendo_super_game_boy = {}
nintendo_super_game_boy[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_super_game_boy[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_super_game_boy[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SUPER_GAME_BOY.value
nintendo_super_game_boy[keys.platform_key_addons] = []
nintendo_super_game_boy[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_super_game_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_game_boy[keys.platform_key_fillonce_json] = []
nintendo_super_game_boy[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_SUPER_GAME_BOY.value] = nintendo_super_game_boy

###########################################################
# Nintendo Super Game Boy Color
###########################################################
nintendo_super_game_boy_color = {}
nintendo_super_game_boy_color[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_super_game_boy_color[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_super_game_boy_color[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SUPER_GAME_BOY_COLOR.value
nintendo_super_game_boy_color[keys.platform_key_addons] = []
nintendo_super_game_boy_color[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_super_game_boy_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_game_boy_color[keys.platform_key_fillonce_json] = []
nintendo_super_game_boy_color[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_SUPER_GAME_BOY_COLOR.value] = nintendo_super_game_boy_color

###########################################################
# Nintendo Switch
###########################################################
nintendo_switch = {}
nintendo_switch[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_switch[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_switch[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SWITCH.value
nintendo_switch[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
nintendo_switch[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_switch[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_switch[keys.platform_key_fillonce_json] = []
nintendo_switch[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_SWITCH.value] = nintendo_switch

###########################################################
# Nintendo Switch eShop
###########################################################
nintendo_switch_eshop = {}
nintendo_switch_eshop[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_switch_eshop[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_switch_eshop[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SWITCH_ESHOP.value
nintendo_switch_eshop[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
nintendo_switch_eshop[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_switch_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_switch_eshop[keys.platform_key_fillonce_json] = []
nintendo_switch_eshop[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_SWITCH_ESHOP.value] = nintendo_switch_eshop

###########################################################
# Nintendo Virtual Boy
###########################################################
nintendo_virtual_boy = {}
nintendo_virtual_boy[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_virtual_boy[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_virtual_boy[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_VIRTUAL_BOY.value
nintendo_virtual_boy[keys.platform_key_addons] = []
nintendo_virtual_boy[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_virtual_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_virtual_boy[keys.platform_key_fillonce_json] = []
nintendo_virtual_boy[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_VIRTUAL_BOY.value] = nintendo_virtual_boy

###########################################################
# Nintendo Wii
###########################################################
nintendo_wii = {}
nintendo_wii[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_wii[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_wii[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_WII.value
nintendo_wii[keys.platform_key_addons] = [types.AddonType.DLC.value]
nintendo_wii[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_wii[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii[keys.platform_key_fillonce_json] = []
nintendo_wii[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_WII.value] = nintendo_wii

###########################################################
# Nintendo Wii U
###########################################################
nintendo_wii_u = {}
nintendo_wii_u[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_wii_u[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_wii_u[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_WII_U.value
nintendo_wii_u[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
nintendo_wii_u[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_wii_u[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii_u[keys.platform_key_fillonce_json] = []
nintendo_wii_u[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_WII_U.value] = nintendo_wii_u

###########################################################
# Nintendo Wii U eShop
###########################################################
nintendo_wii_u_eshop = {}
nintendo_wii_u_eshop[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_wii_u_eshop[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_wii_u_eshop[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_WII_U_ESHOP.value
nintendo_wii_u_eshop[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
nintendo_wii_u_eshop[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_wii_u_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii_u_eshop[keys.platform_key_fillonce_json] = []
nintendo_wii_u_eshop[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_WII_U_ESHOP.value] = nintendo_wii_u_eshop

###########################################################
# Nintendo WiiWare
###########################################################
nintendo_wiiware = {}
nintendo_wiiware[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nintendo_wiiware[keys.platform_key_category] = categories.Category.NINTENDO.value
nintendo_wiiware[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_WIIWARE.value
nintendo_wiiware[keys.platform_key_addons] = [types.AddonType.DLC.value]
nintendo_wiiware[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nintendo_wiiware[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wiiware[keys.platform_key_fillonce_json] = []
nintendo_wiiware[keys.platform_key_merge_json] = []
platforms[NintendoPlatform.NINTENDO_WIIWARE.value] = nintendo_wiiware

######################################################################################

###########################################################
# Apple iOS
###########################################################
apple_ios = {}
apple_ios[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
apple_ios[keys.platform_key_category] = categories.Category.OTHER.value
apple_ios[keys.platform_key_subcategory] = categories.Subcategory.OTHER_APPLE_IOS.value
apple_ios[keys.platform_key_addons] = []
apple_ios[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER.value]
apple_ios[keys.platform_key_autofill_json] = [keys.json_key_files]
apple_ios[keys.platform_key_fillonce_json] = []
apple_ios[keys.platform_key_merge_json] = []
platforms[OtherPlatform.APPLE_IOS.value] = apple_ios

###########################################################
# Apple MacOS 8
###########################################################
apple_macos_8 = {}
apple_macos_8[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
apple_macos_8[keys.platform_key_category] = categories.Category.OTHER.value
apple_macos_8[keys.platform_key_subcategory] = categories.Subcategory.OTHER_APPLE_MACOS_8.value
apple_macos_8[keys.platform_key_addons] = []
apple_macos_8[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
apple_macos_8[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
apple_macos_8[keys.platform_key_fillonce_json] = []
apple_macos_8[keys.platform_key_merge_json] = []
platforms[OtherPlatform.APPLE_MACOS_8.value] = apple_macos_8

###########################################################
# Arcade
###########################################################
arcade = {}
arcade[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
arcade[keys.platform_key_category] = categories.Category.OTHER.value
arcade[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ARCADE.value
arcade[keys.platform_key_addons] = []
arcade[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_NAME.value]
arcade[keys.platform_key_autofill_json] = [keys.json_key_files]
arcade[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
arcade[keys.platform_key_merge_json] = []
platforms[OtherPlatform.ARCADE.value] = arcade

###########################################################
# Atari 800
###########################################################
atari_800 = {}
atari_800[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
atari_800[keys.platform_key_category] = categories.Category.OTHER.value
atari_800[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_800.value
atari_800[keys.platform_key_addons] = []
atari_800[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
atari_800[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_800[keys.platform_key_fillonce_json] = []
atari_800[keys.platform_key_merge_json] = []
platforms[OtherPlatform.ATARI_800.value] = atari_800

###########################################################
# Atari 2600
###########################################################
atari_2600 = {}
atari_2600[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
atari_2600[keys.platform_key_category] = categories.Category.OTHER.value
atari_2600[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_2600.value
atari_2600[keys.platform_key_addons] = []
atari_2600[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
atari_2600[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_2600[keys.platform_key_fillonce_json] = []
atari_2600[keys.platform_key_merge_json] = []
platforms[OtherPlatform.ATARI_2600.value] = atari_2600

###########################################################
# Atari 5200
###########################################################
atari_5200 = {}
atari_5200[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
atari_5200[keys.platform_key_category] = categories.Category.OTHER.value
atari_5200[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_5200.value
atari_5200[keys.platform_key_addons] = []
atari_5200[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
atari_5200[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_5200[keys.platform_key_fillonce_json] = []
atari_5200[keys.platform_key_merge_json] = []
platforms[OtherPlatform.ATARI_5200.value] = atari_5200

###########################################################
# Atari 7800
###########################################################
atari_7800 = {}
atari_7800[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
atari_7800[keys.platform_key_category] = categories.Category.OTHER.value
atari_7800[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_7800.value
atari_7800[keys.platform_key_addons] = []
atari_7800[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
atari_7800[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_7800[keys.platform_key_fillonce_json] = []
atari_7800[keys.platform_key_merge_json] = []
platforms[OtherPlatform.ATARI_7800.value] = atari_7800

###########################################################
# Atari Jaguar
###########################################################
atari_jaguar = {}
atari_jaguar[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
atari_jaguar[keys.platform_key_category] = categories.Category.OTHER.value
atari_jaguar[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_JAGUAR.value
atari_jaguar[keys.platform_key_addons] = []
atari_jaguar[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
atari_jaguar[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_jaguar[keys.platform_key_fillonce_json] = []
atari_jaguar[keys.platform_key_merge_json] = []
platforms[OtherPlatform.ATARI_JAGUAR.value] = atari_jaguar

###########################################################
# Atari Jaguar CD
###########################################################
atari_jaguar_cd = {}
atari_jaguar_cd[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
atari_jaguar_cd[keys.platform_key_category] = categories.Category.OTHER.value
atari_jaguar_cd[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_JAGUAR_CD.value
atari_jaguar_cd[keys.platform_key_addons] = []
atari_jaguar_cd[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
atari_jaguar_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_jaguar_cd[keys.platform_key_fillonce_json] = []
atari_jaguar_cd[keys.platform_key_merge_json] = []
platforms[OtherPlatform.ATARI_JAGUAR_CD.value] = atari_jaguar_cd

###########################################################
# Atari Lynx
###########################################################
atari_lynx = {}
atari_lynx[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
atari_lynx[keys.platform_key_category] = categories.Category.OTHER.value
atari_lynx[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_LYNX.value
atari_lynx[keys.platform_key_addons] = []
atari_lynx[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
atari_lynx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_lynx[keys.platform_key_fillonce_json] = []
atari_lynx[keys.platform_key_merge_json] = []
platforms[OtherPlatform.ATARI_LYNX.value] = atari_lynx

###########################################################
# Bandai WonderSwan
###########################################################
bandai_wonderswan = {}
bandai_wonderswan[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
bandai_wonderswan[keys.platform_key_category] = categories.Category.OTHER.value
bandai_wonderswan[keys.platform_key_subcategory] = categories.Subcategory.OTHER_BANDAI_WONDERSWAN.value
bandai_wonderswan[keys.platform_key_addons] = []
bandai_wonderswan[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
bandai_wonderswan[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
bandai_wonderswan[keys.platform_key_fillonce_json] = []
bandai_wonderswan[keys.platform_key_merge_json] = []
platforms[OtherPlatform.BANDAI_WONDERSWAN.value] = bandai_wonderswan

###########################################################
# Bandai WonderSwan Color
###########################################################
bandai_wonderswan_color = {}
bandai_wonderswan_color[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
bandai_wonderswan_color[keys.platform_key_category] = categories.Category.OTHER.value
bandai_wonderswan_color[keys.platform_key_subcategory] = categories.Subcategory.OTHER_BANDAI_WONDERSWAN_COLOR.value
bandai_wonderswan_color[keys.platform_key_addons] = []
bandai_wonderswan_color[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
bandai_wonderswan_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
bandai_wonderswan_color[keys.platform_key_fillonce_json] = []
bandai_wonderswan_color[keys.platform_key_merge_json] = []
platforms[OtherPlatform.BANDAI_WONDERSWAN_COLOR.value] = bandai_wonderswan_color

###########################################################
# Coleco ColecoVision
###########################################################
coleco_colecovision = {}
coleco_colecovision[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
coleco_colecovision[keys.platform_key_category] = categories.Category.OTHER.value
coleco_colecovision[keys.platform_key_subcategory] = categories.Subcategory.OTHER_COLECO_COLECOVISION.value
coleco_colecovision[keys.platform_key_addons] = []
coleco_colecovision[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
coleco_colecovision[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
coleco_colecovision[keys.platform_key_fillonce_json] = []
coleco_colecovision[keys.platform_key_merge_json] = []
platforms[OtherPlatform.COLECO_COLECOVISION.value] = coleco_colecovision

###########################################################
# Commodore 64
###########################################################
commodore_64 = {}
commodore_64[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
commodore_64[keys.platform_key_category] = categories.Category.OTHER.value
commodore_64[keys.platform_key_subcategory] = categories.Subcategory.OTHER_COMMODORE_64.value
commodore_64[keys.platform_key_addons] = []
commodore_64[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
commodore_64[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
commodore_64[keys.platform_key_fillonce_json] = []
commodore_64[keys.platform_key_merge_json] = []
platforms[OtherPlatform.COMMODORE_64.value] = commodore_64

###########################################################
# Commodore Amiga
###########################################################
commodore_amiga = {}
commodore_amiga[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
commodore_amiga[keys.platform_key_category] = categories.Category.OTHER.value
commodore_amiga[keys.platform_key_subcategory] = categories.Subcategory.OTHER_COMMODORE_AMIGA.value
commodore_amiga[keys.platform_key_addons] = []
commodore_amiga[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
commodore_amiga[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
commodore_amiga[keys.platform_key_fillonce_json] = []
commodore_amiga[keys.platform_key_merge_json] = []
platforms[OtherPlatform.COMMODORE_AMIGA.value] = commodore_amiga

###########################################################
# Google Android
###########################################################
google_android = {}
google_android[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
google_android[keys.platform_key_category] = categories.Category.OTHER.value
google_android[keys.platform_key_subcategory] = categories.Subcategory.OTHER_GOOGLE_ANDROID.value
google_android[keys.platform_key_addons] = []
google_android[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER.value]
google_android[keys.platform_key_autofill_json] = [keys.json_key_files]
google_android[keys.platform_key_fillonce_json] = []
google_android[keys.platform_key_merge_json] = []
platforms[OtherPlatform.GOOGLE_ANDROID.value] = google_android

###########################################################
# Magnavox Odyssey 2
###########################################################
magnavox_odyssey_2 = {}
magnavox_odyssey_2[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
magnavox_odyssey_2[keys.platform_key_category] = categories.Category.OTHER.value
magnavox_odyssey_2[keys.platform_key_subcategory] = categories.Subcategory.OTHER_MAGNAVOX_ODYSSEY_2.value
magnavox_odyssey_2[keys.platform_key_addons] = []
magnavox_odyssey_2[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
magnavox_odyssey_2[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
magnavox_odyssey_2[keys.platform_key_fillonce_json] = []
magnavox_odyssey_2[keys.platform_key_merge_json] = []
platforms[OtherPlatform.MAGNAVOX_ODYSSEY_2.value] = magnavox_odyssey_2

###########################################################
# Mattel Intellivision
###########################################################
mattel_intellivision = {}
mattel_intellivision[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
mattel_intellivision[keys.platform_key_category] = categories.Category.OTHER.value
mattel_intellivision[keys.platform_key_subcategory] = categories.Subcategory.OTHER_MATTEL_INTELLIVISION.value
mattel_intellivision[keys.platform_key_addons] = []
mattel_intellivision[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
mattel_intellivision[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
mattel_intellivision[keys.platform_key_fillonce_json] = []
mattel_intellivision[keys.platform_key_merge_json] = []
platforms[OtherPlatform.MATTEL_INTELLIVISION.value] = mattel_intellivision

###########################################################
# NEC PC-Engine
###########################################################
nec_pcengine = {}
nec_pcengine[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nec_pcengine[keys.platform_key_category] = categories.Category.OTHER.value
nec_pcengine[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_PCENGINE.value
nec_pcengine[keys.platform_key_addons] = []
nec_pcengine[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nec_pcengine[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_pcengine[keys.platform_key_fillonce_json] = []
nec_pcengine[keys.platform_key_merge_json] = []
platforms[OtherPlatform.NEC_PCENGINE.value] = nec_pcengine

###########################################################
# NEC PC-Engine CD
###########################################################
nec_pcengine_cd = {}
nec_pcengine_cd[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nec_pcengine_cd[keys.platform_key_category] = categories.Category.OTHER.value
nec_pcengine_cd[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_PCENGINE_CD.value
nec_pcengine_cd[keys.platform_key_addons] = []
nec_pcengine_cd[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nec_pcengine_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_pcengine_cd[keys.platform_key_fillonce_json] = []
nec_pcengine_cd[keys.platform_key_merge_json] = []
platforms[OtherPlatform.NEC_PCENGINE_CD.value] = nec_pcengine_cd

###########################################################
# NEC SuperGrafx
###########################################################
nec_supergrafx = {}
nec_supergrafx[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nec_supergrafx[keys.platform_key_category] = categories.Category.OTHER.value
nec_supergrafx[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_SUPERGRAFX.value
nec_supergrafx[keys.platform_key_addons] = []
nec_supergrafx[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nec_supergrafx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_supergrafx[keys.platform_key_fillonce_json] = []
nec_supergrafx[keys.platform_key_merge_json] = []
platforms[OtherPlatform.NEC_SUPERGRAFX.value] = nec_supergrafx

###########################################################
# NEC TurboGrafx-16
###########################################################
nec_turbografx_16 = {}
nec_turbografx_16[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nec_turbografx_16[keys.platform_key_category] = categories.Category.OTHER.value
nec_turbografx_16[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_TURBOGRAFX_16.value
nec_turbografx_16[keys.platform_key_addons] = []
nec_turbografx_16[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nec_turbografx_16[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_turbografx_16[keys.platform_key_fillonce_json] = []
nec_turbografx_16[keys.platform_key_merge_json] = []
platforms[OtherPlatform.NEC_TURBOGRAFX_16.value] = nec_turbografx_16

###########################################################
# NEC TurboGrafx CD
###########################################################
nec_turbografx_cd = {}
nec_turbografx_cd[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nec_turbografx_cd[keys.platform_key_category] = categories.Category.OTHER.value
nec_turbografx_cd[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_TURBOGRAFX_CD.value
nec_turbografx_cd[keys.platform_key_addons] = []
nec_turbografx_cd[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
nec_turbografx_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_turbografx_cd[keys.platform_key_fillonce_json] = []
nec_turbografx_cd[keys.platform_key_merge_json] = []
platforms[OtherPlatform.NEC_TURBOGRAFX_CD.value] = nec_turbografx_cd

###########################################################
# Nokia N-Gage
###########################################################
nokia_ngage = {}
nokia_ngage[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
nokia_ngage[keys.platform_key_category] = categories.Category.OTHER.value
nokia_ngage[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NOKIA_NGAGE.value
nokia_ngage[keys.platform_key_addons] = []
nokia_ngage[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_NAME.value]
nokia_ngage[keys.platform_key_autofill_json] = [keys.json_key_files]
nokia_ngage[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
nokia_ngage[keys.platform_key_merge_json] = []
platforms[OtherPlatform.NOKIA_NGAGE.value] = nokia_ngage

###########################################################
# Panasonic 3DO
###########################################################
panasonic_3do = {}
panasonic_3do[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
panasonic_3do[keys.platform_key_category] = categories.Category.OTHER.value
panasonic_3do[keys.platform_key_subcategory] = categories.Subcategory.OTHER_PANASONIC_3DO.value
panasonic_3do[keys.platform_key_addons] = []
panasonic_3do[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
panasonic_3do[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
panasonic_3do[keys.platform_key_fillonce_json] = []
panasonic_3do[keys.platform_key_merge_json] = []
platforms[OtherPlatform.PANASONIC_3DO.value] = panasonic_3do

###########################################################
# Philips CDi
###########################################################
philips_cdi = {}
philips_cdi[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
philips_cdi[keys.platform_key_category] = categories.Category.OTHER.value
philips_cdi[keys.platform_key_subcategory] = categories.Subcategory.OTHER_PHILIPS_CDI.value
philips_cdi[keys.platform_key_addons] = []
philips_cdi[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
philips_cdi[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
philips_cdi[keys.platform_key_fillonce_json] = []
philips_cdi[keys.platform_key_merge_json] = []
platforms[OtherPlatform.PHILIPS_CDI.value] = philips_cdi

###########################################################
# SNK Neo Geo Pocket Color
###########################################################
snk_neogeo_pocket_color = {}
snk_neogeo_pocket_color[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
snk_neogeo_pocket_color[keys.platform_key_category] = categories.Category.OTHER.value
snk_neogeo_pocket_color[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SNK_NEOGEO_POCKET_COLOR.value
snk_neogeo_pocket_color[keys.platform_key_addons] = []
snk_neogeo_pocket_color[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
snk_neogeo_pocket_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
snk_neogeo_pocket_color[keys.platform_key_fillonce_json] = []
snk_neogeo_pocket_color[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SNK_NEOGEO_POCKET_COLOR.value] = snk_neogeo_pocket_color

###########################################################
# Sega 32X
###########################################################
sega_32x = {}
sega_32x[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sega_32x[keys.platform_key_category] = categories.Category.OTHER.value
sega_32x[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_32X.value
sega_32x[keys.platform_key_addons] = []
sega_32x[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sega_32x[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_32x[keys.platform_key_fillonce_json] = []
sega_32x[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SEGA_32X.value] = sega_32x

###########################################################
# Sega CD
###########################################################
sega_cd = {}
sega_cd[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sega_cd[keys.platform_key_category] = categories.Category.OTHER.value
sega_cd[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_CD.value
sega_cd[keys.platform_key_addons] = []
sega_cd[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sega_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_cd[keys.platform_key_fillonce_json] = []
sega_cd[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SEGA_CD.value] = sega_cd

###########################################################
# Sega CD 32X
###########################################################
sega_cd_32x = {}
sega_cd_32x[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sega_cd_32x[keys.platform_key_category] = categories.Category.OTHER.value
sega_cd_32x[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_CD_32X.value
sega_cd_32x[keys.platform_key_addons] = []
sega_cd_32x[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sega_cd_32x[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_cd_32x[keys.platform_key_fillonce_json] = []
sega_cd_32x[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SEGA_CD_32X.value] = sega_cd_32x

###########################################################
# Sega Dreamcast
###########################################################
sega_dreamcast = {}
sega_dreamcast[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sega_dreamcast[keys.platform_key_category] = categories.Category.OTHER.value
sega_dreamcast[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_DREAMCAST.value
sega_dreamcast[keys.platform_key_addons] = []
sega_dreamcast[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sega_dreamcast[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_dreamcast[keys.platform_key_fillonce_json] = []
sega_dreamcast[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SEGA_DREAMCAST.value] = sega_dreamcast

###########################################################
# Sega Game Gear
###########################################################
sega_game_gear = {}
sega_game_gear[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sega_game_gear[keys.platform_key_category] = categories.Category.OTHER.value
sega_game_gear[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_GAME_GEAR.value
sega_game_gear[keys.platform_key_addons] = []
sega_game_gear[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sega_game_gear[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_game_gear[keys.platform_key_fillonce_json] = []
sega_game_gear[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SEGA_GAME_GEAR.value] = sega_game_gear

###########################################################
# Sega Genesis
###########################################################
sega_genesis = {}
sega_genesis[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sega_genesis[keys.platform_key_category] = categories.Category.OTHER.value
sega_genesis[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_GENESIS.value
sega_genesis[keys.platform_key_addons] = []
sega_genesis[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sega_genesis[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_genesis[keys.platform_key_fillonce_json] = []
sega_genesis[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SEGA_GENESIS.value] = sega_genesis

###########################################################
# Sega Master System
###########################################################
sega_master_system = {}
sega_master_system[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sega_master_system[keys.platform_key_category] = categories.Category.OTHER.value
sega_master_system[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_MASTER_SYSTEM.value
sega_master_system[keys.platform_key_addons] = []
sega_master_system[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sega_master_system[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_master_system[keys.platform_key_fillonce_json] = []
sega_master_system[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SEGA_MASTER_SYSTEM.value] = sega_master_system

###########################################################
# Sega Saturn
###########################################################
sega_saturn = {}
sega_saturn[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sega_saturn[keys.platform_key_category] = categories.Category.OTHER.value
sega_saturn[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_SATURN.value
sega_saturn[keys.platform_key_addons] = []
sega_saturn[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sega_saturn[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_saturn[keys.platform_key_fillonce_json] = []
sega_saturn[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SEGA_SATURN.value] = sega_saturn

###########################################################
# Sinclair ZX Spectrum
###########################################################
sinclair_zx_spectrum = {}
sinclair_zx_spectrum[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sinclair_zx_spectrum[keys.platform_key_category] = categories.Category.OTHER.value
sinclair_zx_spectrum[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SINCLAIR_ZX_SPECTRUM.value
sinclair_zx_spectrum[keys.platform_key_addons] = []
sinclair_zx_spectrum[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sinclair_zx_spectrum[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sinclair_zx_spectrum[keys.platform_key_fillonce_json] = []
sinclair_zx_spectrum[keys.platform_key_merge_json] = []
platforms[OtherPlatform.SINCLAIR_ZX_SPECTRUM.value] = sinclair_zx_spectrum

###########################################################
# Texas Instruments TI-99-4A
###########################################################
texas_instruments_ti994a = {}
texas_instruments_ti994a[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
texas_instruments_ti994a[keys.platform_key_category] = categories.Category.OTHER.value
texas_instruments_ti994a[keys.platform_key_subcategory] = categories.Subcategory.OTHER_TEXAS_INSTRUMENTS_TI994A.value
texas_instruments_ti994a[keys.platform_key_addons] = []
texas_instruments_ti994a[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
texas_instruments_ti994a[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
texas_instruments_ti994a[keys.platform_key_fillonce_json] = []
texas_instruments_ti994a[keys.platform_key_merge_json] = []
platforms[OtherPlatform.TEXAS_INSTRUMENTS_TI994A.value] = texas_instruments_ti994a

###########################################################
# Tiger Game.com
###########################################################
tiger_gamecom = {}
tiger_gamecom[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
tiger_gamecom[keys.platform_key_category] = categories.Category.OTHER.value
tiger_gamecom[keys.platform_key_subcategory] = categories.Subcategory.OTHER_TIGER_GAMECOM.value
tiger_gamecom[keys.platform_key_addons] = []
tiger_gamecom[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
tiger_gamecom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
tiger_gamecom[keys.platform_key_fillonce_json] = []
tiger_gamecom[keys.platform_key_merge_json] = []
platforms[OtherPlatform.TIGER_GAMECOM.value] = tiger_gamecom

######################################################################################

###########################################################
# Sony PlayStation
###########################################################
sony_playstation = {}
sony_playstation[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION.value
sony_playstation[keys.platform_key_addons] = []
sony_playstation[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sony_playstation[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation[keys.platform_key_fillonce_json] = []
sony_playstation[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION.value] = sony_playstation

###########################################################
# Sony PlayStation 2
###########################################################
sony_playstation_2 = {}
sony_playstation_2[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_2[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_2[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_2.value
sony_playstation_2[keys.platform_key_addons] = []
sony_playstation_2[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sony_playstation_2[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_2[keys.platform_key_fillonce_json] = []
sony_playstation_2[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_2.value] = sony_playstation_2

###########################################################
# Sony PlayStation 3
###########################################################
sony_playstation_3 = {}
sony_playstation_3[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_3[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_3[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_3.value
sony_playstation_3[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
sony_playstation_3[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sony_playstation_3[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_3[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
sony_playstation_3[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_3.value] = sony_playstation_3

###########################################################
# Sony PlayStation 4
###########################################################
sony_playstation_4 = {}
sony_playstation_4[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_4[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_4[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_4.value
sony_playstation_4[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
sony_playstation_4[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER.value]
sony_playstation_4[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_4[keys.platform_key_fillonce_json] = []
sony_playstation_4[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_4.value] = sony_playstation_4

###########################################################
# Sony PlayStation Network - PlayStation 3
###########################################################
sony_playstation_network_ps3 = {}
sony_playstation_network_ps3[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_network_ps3[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_network_ps3[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS3.value
sony_playstation_network_ps3[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
sony_playstation_network_ps3[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sony_playstation_network_ps3[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_network_ps3[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
sony_playstation_network_ps3[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_NETWORK_PS3.value] = sony_playstation_network_ps3

###########################################################
# Sony PlayStation Network - PlayStation 4
###########################################################
sony_playstation_network_ps4 = {}
sony_playstation_network_ps4[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_network_ps4[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_network_ps4[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS4.value
sony_playstation_network_ps4[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
sony_playstation_network_ps4[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER.value]
sony_playstation_network_ps4[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_network_ps4[keys.platform_key_fillonce_json] = []
sony_playstation_network_ps4[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_NETWORK_PS4.value] = sony_playstation_network_ps4

###########################################################
# Sony PlayStation Network - PlayStation Portable
###########################################################
sony_playstation_network_psp = {}
sony_playstation_network_psp[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_network_psp[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_network_psp[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSP.value
sony_playstation_network_psp[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
sony_playstation_network_psp[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sony_playstation_network_psp[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_network_psp[keys.platform_key_fillonce_json] = []
sony_playstation_network_psp[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_NETWORK_PSP.value] = sony_playstation_network_psp

###########################################################
# Sony PlayStation Network - PlayStation Portable Minis
###########################################################
sony_playstation_network_pspm = {}
sony_playstation_network_pspm[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_network_pspm[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_network_pspm[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSPM.value
sony_playstation_network_pspm[keys.platform_key_addons] = []
sony_playstation_network_pspm[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sony_playstation_network_pspm[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_network_pspm[keys.platform_key_fillonce_json] = []
sony_playstation_network_pspm[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_NETWORK_PSPM.value] = sony_playstation_network_pspm

###########################################################
# Sony PlayStation Network - PlayStation Vita
###########################################################
sony_playstation_network_psv = {}
sony_playstation_network_psv[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_network_psv[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_network_psv[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSV.value
sony_playstation_network_psv[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
sony_playstation_network_psv[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_NAME.value]
sony_playstation_network_psv[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_network_psv[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
sony_playstation_network_psv[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_NETWORK_PSV.value] = sony_playstation_network_psv

###########################################################
# Sony PlayStation Portable
###########################################################
sony_playstation_portable = {}
sony_playstation_portable[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_portable[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_portable[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_PORTABLE.value
sony_playstation_portable[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
sony_playstation_portable[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE.value]
sony_playstation_portable[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_portable[keys.platform_key_fillonce_json] = []
sony_playstation_portable[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_PORTABLE.value] = sony_playstation_portable

###########################################################
# Sony PlayStation Portable Video
###########################################################
sony_playstation_portable_video = {}
sony_playstation_portable_video[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_portable_video[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_portable_video[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_PORTABLE_VIDEO.value
sony_playstation_portable_video[keys.platform_key_addons] = []
sony_playstation_portable_video[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER.value]
sony_playstation_portable_video[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_portable_video[keys.platform_key_fillonce_json] = []
sony_playstation_portable_video[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_PORTABLE_VIDEO.value] = sony_playstation_portable_video

###########################################################
# Sony PlayStation Vita
###########################################################
sony_playstation_vita = {}
sony_playstation_vita[keys.platform_key_supercategory] = categories.Supercategory.ROMS.value
sony_playstation_vita[keys.platform_key_category] = categories.Category.SONY.value
sony_playstation_vita[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_VITA.value
sony_playstation_vita[keys.platform_key_addons] = [types.AddonType.DLC.value, types.AddonType.UPDATES.value]
sony_playstation_vita[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_NAME.value]
sony_playstation_vita[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_vita[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
sony_playstation_vita[keys.platform_key_merge_json] = []
platforms[SonyPlatform.SONY_PLAYSTATION_VITA.value] = sony_playstation_vita
