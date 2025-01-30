# Imports
import os
import sys

# Local imports
from . import categories
from . import keys
from . import types

# Platforms
class Platform(types.EnumType):

    # Computer
    COMPUTER_AMAZON_GAMES               = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_AMAZON_GAMES.val())
    COMPUTER_DISC                       = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_DISC.val())
    COMPUTER_EPIC_GAMES                 = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_EPIC_GAMES.val())
    COMPUTER_GOG                        = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_GOG.val())
    COMPUTER_HUMBLE_BUNDLE              = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_HUMBLE_BUNDLE.val())
    COMPUTER_ITCHIO                     = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_ITCHIO.val())
    COMPUTER_LEGACY_GAMES               = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_LEGACY_GAMES.val())
    COMPUTER_PUPPET_COMBO               = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_PUPPET_COMBO.val())
    COMPUTER_RED_CANDLE                 = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_RED_CANDLE.val())
    COMPUTER_SQUARE_ENIX                = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_SQUARE_ENIX.val())
    COMPUTER_STEAM                      = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_STEAM.val())
    COMPUTER_ZOOM                       = (categories.Category.COMPUTER.val() + " - " + categories.Subcategory.COMPUTER_ZOOM.val())

    # Microsoft
    MICROSOFT_MSX                       = (categories.Subcategory.MICROSOFT_MSX.val())
    MICROSOFT_XBOX                      = (categories.Subcategory.MICROSOFT_XBOX.val())
    MICROSOFT_XBOX_360                  = (categories.Subcategory.MICROSOFT_XBOX_360.val())
    MICROSOFT_XBOX_360_GOD              = (categories.Subcategory.MICROSOFT_XBOX_360_GOD.val())
    MICROSOFT_XBOX_360_XBLA             = (categories.Subcategory.MICROSOFT_XBOX_360_XBLA.val())
    MICROSOFT_XBOX_360_XIG              = (categories.Subcategory.MICROSOFT_XBOX_360_XIG.val())
    MICROSOFT_XBOX_ONE                  = (categories.Subcategory.MICROSOFT_XBOX_ONE.val())
    MICROSOFT_XBOX_ONE_GOD              = (categories.Subcategory.MICROSOFT_XBOX_ONE_GOD.val())

    # Nintendo
    NINTENDO_3DS                        = (categories.Subcategory.NINTENDO_3DS.val())
    NINTENDO_3DS_APPS                   = (categories.Subcategory.NINTENDO_3DS_APPS.val())
    NINTENDO_3DS_ESHOP                  = (categories.Subcategory.NINTENDO_3DS_ESHOP.val())
    NINTENDO_64                         = (categories.Subcategory.NINTENDO_64.val())
    NINTENDO_AMIIBO                     = (categories.Subcategory.NINTENDO_AMIIBO.val())
    NINTENDO_DS                         = (categories.Subcategory.NINTENDO_DS.val())
    NINTENDO_DSI                        = (categories.Subcategory.NINTENDO_DSI.val())
    NINTENDO_FAMICOM                    = (categories.Subcategory.NINTENDO_FAMICOM.val())
    NINTENDO_GAME_BOY                   = (categories.Subcategory.NINTENDO_GAME_BOY.val())
    NINTENDO_GAME_BOY_ADVANCE           = (categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE.val())
    NINTENDO_GAME_BOY_ADVANCE_EREADER   = (categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE_EREADER.val())
    NINTENDO_GAME_BOY_COLOR             = (categories.Subcategory.NINTENDO_GAME_BOY_COLOR.val())
    NINTENDO_GAMECUBE                   = (categories.Subcategory.NINTENDO_GAMECUBE.val())
    NINTENDO_NES                        = (categories.Subcategory.NINTENDO_NES.val())
    NINTENDO_SNES                       = (categories.Subcategory.NINTENDO_SNES.val())
    NINTENDO_SNES_MSU1                  = (categories.Subcategory.NINTENDO_SNES_MSU1.val())
    NINTENDO_SUPER_FAMICOM              = (categories.Subcategory.NINTENDO_SUPER_FAMICOM.val())
    NINTENDO_SUPER_GAME_BOY             = (categories.Subcategory.NINTENDO_SUPER_GAME_BOY.val())
    NINTENDO_SUPER_GAME_BOY_COLOR       = (categories.Subcategory.NINTENDO_SUPER_GAME_BOY_COLOR.val())
    NINTENDO_SWITCH                     = (categories.Subcategory.NINTENDO_SWITCH.val())
    NINTENDO_SWITCH_ESHOP               = (categories.Subcategory.NINTENDO_SWITCH_ESHOP.val())
    NINTENDO_VIRTUAL_BOY                = (categories.Subcategory.NINTENDO_VIRTUAL_BOY.val())
    NINTENDO_WII                        = (categories.Subcategory.NINTENDO_WII.val())
    NINTENDO_WII_U                      = (categories.Subcategory.NINTENDO_WII_U.val())
    NINTENDO_WII_U_ESHOP                = (categories.Subcategory.NINTENDO_WII_U_ESHOP.val())
    NINTENDO_WIIWARE                    = (categories.Subcategory.NINTENDO_WIIWARE.val())

    # Other
    OTHER_APPLE_IOS                     = (categories.Subcategory.OTHER_APPLE_IOS.val())
    OTHER_APPLE_MACOS_8                 = (categories.Subcategory.OTHER_APPLE_MACOS_8.val())
    OTHER_ARCADE                        = (categories.Subcategory.OTHER_ARCADE.val())
    OTHER_ATARI_800                     = (categories.Subcategory.OTHER_ATARI_800.val())
    OTHER_ATARI_2600                    = (categories.Subcategory.OTHER_ATARI_2600.val())
    OTHER_ATARI_5200                    = (categories.Subcategory.OTHER_ATARI_5200.val())
    OTHER_ATARI_7800                    = (categories.Subcategory.OTHER_ATARI_7800.val())
    OTHER_ATARI_JAGUAR                  = (categories.Subcategory.OTHER_ATARI_JAGUAR.val())
    OTHER_ATARI_JAGUAR_CD               = (categories.Subcategory.OTHER_ATARI_JAGUAR_CD.val())
    OTHER_ATARI_LYNX                    = (categories.Subcategory.OTHER_ATARI_LYNX.val())
    OTHER_BANDAI_WONDERSWAN             = (categories.Subcategory.OTHER_BANDAI_WONDERSWAN.val())
    OTHER_BANDAI_WONDERSWAN_COLOR       = (categories.Subcategory.OTHER_BANDAI_WONDERSWAN_COLOR.val())
    OTHER_COLECO_COLECOVISION           = (categories.Subcategory.OTHER_COLECO_COLECOVISION.val())
    OTHER_COMMODORE_64                  = (categories.Subcategory.OTHER_COMMODORE_64.val())
    OTHER_COMMODORE_AMIGA               = (categories.Subcategory.OTHER_COMMODORE_AMIGA.val())
    OTHER_GOOGLE_ANDROID                = (categories.Subcategory.OTHER_GOOGLE_ANDROID.val())
    OTHER_MAGNAVOX_ODYSSEY_2            = (categories.Subcategory.OTHER_MAGNAVOX_ODYSSEY_2.val())
    OTHER_MATTEL_INTELLIVISION          = (categories.Subcategory.OTHER_MATTEL_INTELLIVISION.val())
    OTHER_NEC_PCENGINE                  = (categories.Subcategory.OTHER_NEC_PCENGINE.val())
    OTHER_NEC_PCENGINE_CD               = (categories.Subcategory.OTHER_NEC_PCENGINE_CD.val())
    OTHER_NEC_SUPERGRAFX                = (categories.Subcategory.OTHER_NEC_SUPERGRAFX.val())
    OTHER_NEC_TURBOGRAFX_16             = (categories.Subcategory.OTHER_NEC_TURBOGRAFX_16.val())
    OTHER_NEC_TURBOGRAFX_CD             = (categories.Subcategory.OTHER_NEC_TURBOGRAFX_CD.val())
    OTHER_NOKIA_NGAGE                   = (categories.Subcategory.OTHER_NOKIA_NGAGE.val())
    OTHER_PANASONIC_3DO                 = (categories.Subcategory.OTHER_PANASONIC_3DO.val())
    OTHER_PHILIPS_CDI                   = (categories.Subcategory.OTHER_PHILIPS_CDI.val())
    OTHER_SNK_NEOGEO_POCKET_COLOR       = (categories.Subcategory.OTHER_SNK_NEOGEO_POCKET_COLOR.val())
    OTHER_SEGA_32X                      = (categories.Subcategory.OTHER_SEGA_32X.val())
    OTHER_SEGA_CD                       = (categories.Subcategory.OTHER_SEGA_CD.val())
    OTHER_SEGA_CD_32X                   = (categories.Subcategory.OTHER_SEGA_CD_32X.val())
    OTHER_SEGA_DREAMCAST                = (categories.Subcategory.OTHER_SEGA_DREAMCAST.val())
    OTHER_SEGA_GAME_GEAR                = (categories.Subcategory.OTHER_SEGA_GAME_GEAR.val())
    OTHER_SEGA_GENESIS                  = (categories.Subcategory.OTHER_SEGA_GENESIS.val())
    OTHER_SEGA_MASTER_SYSTEM            = (categories.Subcategory.OTHER_SEGA_MASTER_SYSTEM.val())
    OTHER_SEGA_SATURN                   = (categories.Subcategory.OTHER_SEGA_SATURN.val())
    OTHER_SINCLAIR_ZX_SPECTRUM          = (categories.Subcategory.OTHER_SINCLAIR_ZX_SPECTRUM.val())
    OTHER_TEXAS_INSTRUMENTS_TI994A      = (categories.Subcategory.OTHER_TEXAS_INSTRUMENTS_TI994A.val())
    OTHER_TIGER_GAMECOM                 = (categories.Subcategory.OTHER_TIGER_GAMECOM.val())

    # Sony
    SONY_PLAYSTATION                    = (categories.Subcategory.SONY_PLAYSTATION.val())
    SONY_PLAYSTATION_2                  = (categories.Subcategory.SONY_PLAYSTATION_2.val())
    SONY_PLAYSTATION_3                  = (categories.Subcategory.SONY_PLAYSTATION_3.val())
    SONY_PLAYSTATION_4                  = (categories.Subcategory.SONY_PLAYSTATION_4.val())
    SONY_PLAYSTATION_NETWORK_PS3        = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS3.val())
    SONY_PLAYSTATION_NETWORK_PS4        = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS4.val())
    SONY_PLAYSTATION_NETWORK_PSP        = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSP.val())
    SONY_PLAYSTATION_NETWORK_PSPM       = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSPM.val())
    SONY_PLAYSTATION_NETWORK_PSV        = (categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSV.val())
    SONY_PLAYSTATION_PORTABLE           = (categories.Subcategory.SONY_PLAYSTATION_PORTABLE.val())
    SONY_PLAYSTATION_PORTABLE_VIDEO     = (categories.Subcategory.SONY_PLAYSTATION_PORTABLE_VIDEO.val())
    SONY_PLAYSTATION_VITA               = (categories.Subcategory.SONY_PLAYSTATION_VITA.val())

######################################################################################

# Transform platforms
transform_platforms = [

    # Computer
    Platform.COMPUTER_AMAZON_GAMES,
    Platform.COMPUTER_DISC,
    Platform.COMPUTER_EPIC_GAMES,
    Platform.COMPUTER_GOG,
    Platform.COMPUTER_HUMBLE_BUNDLE,
    Platform.COMPUTER_ITCHIO,
    Platform.COMPUTER_LEGACY_GAMES,
    Platform.COMPUTER_PUPPET_COMBO,
    Platform.COMPUTER_RED_CANDLE,
    Platform.COMPUTER_SQUARE_ENIX,
    Platform.COMPUTER_STEAM,
    Platform.COMPUTER_ZOOM,

    # Microsoft
    Platform.MICROSOFT_XBOX,
    Platform.MICROSOFT_XBOX_360,

    # Sony
    Platform.SONY_PLAYSTATION_3,
    Platform.SONY_PLAYSTATION_NETWORK_PS3,
    Platform.SONY_PLAYSTATION_NETWORK_PSV
]

# Letter platforms
letter_platforms = [

    # Computer
    Platform.COMPUTER_AMAZON_GAMES,
    Platform.COMPUTER_DISC,
    Platform.COMPUTER_EPIC_GAMES,
    Platform.COMPUTER_GOG,
    Platform.COMPUTER_HUMBLE_BUNDLE,
    Platform.COMPUTER_ITCHIO,
    Platform.COMPUTER_LEGACY_GAMES,
    Platform.COMPUTER_PUPPET_COMBO,
    Platform.COMPUTER_RED_CANDLE,
    Platform.COMPUTER_SQUARE_ENIX,
    Platform.COMPUTER_STEAM,
    Platform.COMPUTER_ZOOM
]

######################################################################################

# Computer autofill json keys
json_keys_autofill_computer = [
    keys.json_key_files,
    keys.json_key_dlc,
    keys.json_key_update,
    keys.json_key_extra,
    keys.json_key_dependencies,
    keys.json_key_transform_file,
    keys.json_key_store_builddate,
    keys.json_key_store_buildid,
    keys.json_key_store_name,
    keys.json_key_store_controller_support,
    keys.json_key_store_installdir
]

# Computer fillonce json keys
json_keys_fillonce_computer = [
    keys.json_key_store_appid,
    keys.json_key_store_appname,
    keys.json_key_store_appurl,
    keys.json_key_store_branchid
]

# Computer merge json keys
json_keys_merge_computer = [
    keys.json_key_store_paths,
    keys.json_key_store_keys,
    keys.json_key_store_launch,
    keys.json_key_store_setup
]

# Platforms
platforms = {}

###########################################################
# Computer - Amazon Games
###########################################################
computer_amazon_games = {}
computer_amazon_games[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_amazon_games[keys.platform_key_category] = categories.Category.COMPUTER
computer_amazon_games[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_AMAZON_GAMES
computer_amazon_games[keys.platform_key_addons] = []
computer_amazon_games[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_amazon_games[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_amazon_games[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_amazon_games[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_amazon]
platforms[Platform.COMPUTER_AMAZON_GAMES] = computer_amazon_games

###########################################################
# Computer - Disc
###########################################################
computer_disc = {}
computer_disc[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_disc[keys.platform_key_category] = categories.Category.COMPUTER
computer_disc[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_DISC
computer_disc[keys.platform_key_addons] = []
computer_disc[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_disc[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_disc[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_disc[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_disc]
platforms[Platform.COMPUTER_DISC] = computer_disc

###########################################################
# Computer - Epic Games
###########################################################
computer_epic_games = {}
computer_epic_games[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_epic_games[keys.platform_key_category] = categories.Category.COMPUTER
computer_epic_games[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_EPIC_GAMES
computer_epic_games[keys.platform_key_addons] = []
computer_epic_games[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_epic_games[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_epic_games[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_epic_games[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_epic]
platforms[Platform.COMPUTER_EPIC_GAMES] = computer_epic_games

###########################################################
# Computer - GOG
###########################################################
computer_gog = {}
computer_gog[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_gog[keys.platform_key_category] = categories.Category.COMPUTER
computer_gog[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_GOG
computer_gog[keys.platform_key_addons] = []
computer_gog[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_gog[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_gog[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_gog[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_gog]
platforms[Platform.COMPUTER_GOG] = computer_gog

###########################################################
# Computer - Humble Bundle
###########################################################
computer_humble_bundle = {}
computer_humble_bundle[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_humble_bundle[keys.platform_key_category] = categories.Category.COMPUTER
computer_humble_bundle[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_HUMBLE_BUNDLE
computer_humble_bundle[keys.platform_key_addons] = []
computer_humble_bundle[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_humble_bundle[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_humble_bundle[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_humble_bundle[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_humble]
platforms[Platform.COMPUTER_HUMBLE_BUNDLE] = computer_humble_bundle

###########################################################
# Computer - Itchio
###########################################################
computer_itchio = {}
computer_itchio[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_itchio[keys.platform_key_category] = categories.Category.COMPUTER
computer_itchio[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_ITCHIO
computer_itchio[keys.platform_key_addons] = []
computer_itchio[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_itchio[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_itchio[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_itchio[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_itchio]
platforms[Platform.COMPUTER_ITCHIO] = computer_itchio

###########################################################
# Computer - Legacy Games
###########################################################
computer_legacy_games = {}
computer_legacy_games[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_legacy_games[keys.platform_key_category] = categories.Category.COMPUTER
computer_legacy_games[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_LEGACY_GAMES
computer_legacy_games[keys.platform_key_addons] = []
computer_legacy_games[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_legacy_games[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_legacy_games[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_legacy_games[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_legacy]
platforms[Platform.COMPUTER_LEGACY_GAMES] = computer_legacy_games

###########################################################
# Computer - Puppet Combo
###########################################################
computer_puppet_combo = {}
computer_puppet_combo[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_puppet_combo[keys.platform_key_category] = categories.Category.COMPUTER
computer_puppet_combo[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_PUPPET_COMBO
computer_puppet_combo[keys.platform_key_addons] = []
computer_puppet_combo[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_puppet_combo[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_puppet_combo[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_puppet_combo[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_puppetcombo]
platforms[Platform.COMPUTER_PUPPET_COMBO] = computer_puppet_combo

###########################################################
# Computer - Red Candle
###########################################################
computer_red_candle = {}
computer_red_candle[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_red_candle[keys.platform_key_category] = categories.Category.COMPUTER
computer_red_candle[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_RED_CANDLE
computer_red_candle[keys.platform_key_addons] = []
computer_red_candle[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_red_candle[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_red_candle[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_red_candle[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_redcandle]
platforms[Platform.COMPUTER_RED_CANDLE] = computer_red_candle

###########################################################
# Computer - Square Enix
###########################################################
computer_square_enix = {}
computer_square_enix[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_square_enix[keys.platform_key_category] = categories.Category.COMPUTER
computer_square_enix[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_SQUARE_ENIX
computer_square_enix[keys.platform_key_addons] = []
computer_square_enix[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_square_enix[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_square_enix[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_square_enix[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_squareenix]
platforms[Platform.COMPUTER_SQUARE_ENIX] = computer_square_enix

###########################################################
# Computer - Steam
###########################################################
computer_steam = {}
computer_steam[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_steam[keys.platform_key_category] = categories.Category.COMPUTER
computer_steam[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_STEAM
computer_steam[keys.platform_key_addons] = []
computer_steam[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_steam[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_steam[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_steam[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_steam]
platforms[Platform.COMPUTER_STEAM] = computer_steam

###########################################################
# Computer - Zoom
###########################################################
computer_zoom = {}
computer_zoom[keys.platform_key_supercategory] = categories.Supercategory.ROMS
computer_zoom[keys.platform_key_category] = categories.Category.COMPUTER
computer_zoom[keys.platform_key_subcategory] = categories.Subcategory.COMPUTER_ZOOM
computer_zoom[keys.platform_key_addons] = []
computer_zoom[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
computer_zoom[keys.platform_key_autofill_json] = json_keys_autofill_computer
computer_zoom[keys.platform_key_fillonce_json] = json_keys_fillonce_computer
computer_zoom[keys.platform_key_merge_json] = json_keys_merge_computer + [keys.json_key_zoom]
platforms[Platform.COMPUTER_ZOOM] = computer_zoom

######################################################################################

###########################################################
# Microsoft MSX
###########################################################
microsoft_msx = {}
microsoft_msx[keys.platform_key_supercategory] = categories.Supercategory.ROMS
microsoft_msx[keys.platform_key_category] = categories.Category.MICROSOFT
microsoft_msx[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_MSX
microsoft_msx[keys.platform_key_addons] = []
microsoft_msx[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
microsoft_msx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
microsoft_msx[keys.platform_key_fillonce_json] = []
microsoft_msx[keys.platform_key_merge_json] = []
platforms[Platform.MICROSOFT_MSX] = microsoft_msx

###########################################################
# Microsoft Xbox
###########################################################
microsoft_xbox = {}
microsoft_xbox[keys.platform_key_supercategory] = categories.Supercategory.ROMS
microsoft_xbox[keys.platform_key_category] = categories.Category.MICROSOFT
microsoft_xbox[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX
microsoft_xbox[keys.platform_key_addons] = []
microsoft_xbox[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
microsoft_xbox[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
microsoft_xbox[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox[keys.platform_key_merge_json] = []
platforms[Platform.MICROSOFT_XBOX] = microsoft_xbox

###########################################################
# Microsoft Xbox 360
###########################################################
microsoft_xbox_360 = {}
microsoft_xbox_360[keys.platform_key_supercategory] = categories.Supercategory.ROMS
microsoft_xbox_360[keys.platform_key_category] = categories.Category.MICROSOFT
microsoft_xbox_360[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_360
microsoft_xbox_360[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
microsoft_xbox_360[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
microsoft_xbox_360[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
microsoft_xbox_360[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox_360[keys.platform_key_merge_json] = []
platforms[Platform.MICROSOFT_XBOX_360] = microsoft_xbox_360

###########################################################
# Microsoft Xbox 360 GOD
###########################################################
microsoft_xbox_360_god = {}
microsoft_xbox_360_god[keys.platform_key_supercategory] = categories.Supercategory.ROMS
microsoft_xbox_360_god[keys.platform_key_category] = categories.Category.MICROSOFT
microsoft_xbox_360_god[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_360_GOD
microsoft_xbox_360_god[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
microsoft_xbox_360_god[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
microsoft_xbox_360_god[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_god[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox_360_god[keys.platform_key_merge_json] = []
platforms[Platform.MICROSOFT_XBOX_360_GOD] = microsoft_xbox_360_god

###########################################################
# Microsoft Xbox 360 XBLA
###########################################################
microsoft_xbox_360_xbla = {}
microsoft_xbox_360_xbla[keys.platform_key_supercategory] = categories.Supercategory.ROMS
microsoft_xbox_360_xbla[keys.platform_key_category] = categories.Category.MICROSOFT
microsoft_xbox_360_xbla[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_360_XBLA
microsoft_xbox_360_xbla[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
microsoft_xbox_360_xbla[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
microsoft_xbox_360_xbla[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_xbla[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox_360_xbla[keys.platform_key_merge_json] = []
platforms[Platform.MICROSOFT_XBOX_360_XBLA] = microsoft_xbox_360_xbla

###########################################################
# Microsoft Xbox 360 XIG
###########################################################
microsoft_xbox_360_xig = {}
microsoft_xbox_360_xig[keys.platform_key_supercategory] = categories.Supercategory.ROMS
microsoft_xbox_360_xig[keys.platform_key_category] = categories.Category.MICROSOFT
microsoft_xbox_360_xig[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_360_XIG
microsoft_xbox_360_xig[keys.platform_key_addons] = []
microsoft_xbox_360_xig[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
microsoft_xbox_360_xig[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_360_xig[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
microsoft_xbox_360_xig[keys.platform_key_merge_json] = []
platforms[Platform.MICROSOFT_XBOX_360_XIG] = microsoft_xbox_360_xig

###########################################################
# Microsoft Xbox One
###########################################################
microsoft_xbox_one = {}
microsoft_xbox_one[keys.platform_key_supercategory] = categories.Supercategory.ROMS
microsoft_xbox_one[keys.platform_key_category] = categories.Category.MICROSOFT
microsoft_xbox_one[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_ONE
microsoft_xbox_one[keys.platform_key_addons] = []
microsoft_xbox_one[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER]
microsoft_xbox_one[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_one[keys.platform_key_fillonce_json] = []
microsoft_xbox_one[keys.platform_key_merge_json] = []
platforms[Platform.MICROSOFT_XBOX_ONE] = microsoft_xbox_one

###########################################################
# Microsoft Xbox One GOD
###########################################################
microsoft_xbox_one_god = {}
microsoft_xbox_one_god[keys.platform_key_supercategory] = categories.Supercategory.ROMS
microsoft_xbox_one_god[keys.platform_key_category] = categories.Category.MICROSOFT
microsoft_xbox_one_god[keys.platform_key_subcategory] = categories.Subcategory.MICROSOFT_XBOX_ONE_GOD
microsoft_xbox_one_god[keys.platform_key_addons] = []
microsoft_xbox_one_god[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER]
microsoft_xbox_one_god[keys.platform_key_autofill_json] = [keys.json_key_files]
microsoft_xbox_one_god[keys.platform_key_fillonce_json] = []
microsoft_xbox_one_god[keys.platform_key_merge_json] = []
platforms[Platform.MICROSOFT_XBOX_ONE_GOD] = microsoft_xbox_one_god

######################################################################################

###########################################################
# Nintendo 3DS
###########################################################
nintendo_3ds = {}
nintendo_3ds[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_3ds[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_3ds[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_3DS
nintendo_3ds[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
nintendo_3ds[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_3ds[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_3ds[keys.platform_key_fillonce_json] = []
nintendo_3ds[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_3DS] = nintendo_3ds

###########################################################
# Nintendo 3DS Apps
###########################################################
nintendo_3ds_apps = {}
nintendo_3ds_apps[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_3ds_apps[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_3ds_apps[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_3DS_APPS
nintendo_3ds_apps[keys.platform_key_addons] = []
nintendo_3ds_apps[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER]
nintendo_3ds_apps[keys.platform_key_autofill_json] = [keys.json_key_files]
nintendo_3ds_apps[keys.platform_key_fillonce_json] = []
nintendo_3ds_apps[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_3DS_APPS] = nintendo_3ds_apps

###########################################################
# Nintendo 3DS eShop
###########################################################
nintendo_3ds_eshop = {}
nintendo_3ds_eshop[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_3ds_eshop[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_3ds_eshop[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_3DS_ESHOP
nintendo_3ds_eshop[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
nintendo_3ds_eshop[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_3ds_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_3ds_eshop[keys.platform_key_fillonce_json] = []
nintendo_3ds_eshop[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_3DS_ESHOP] = nintendo_3ds_eshop

###########################################################
# Nintendo 64
###########################################################
nintendo_64 = {}
nintendo_64[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_64[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_64[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_64
nintendo_64[keys.platform_key_addons] = []
nintendo_64[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_64[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_64[keys.platform_key_fillonce_json] = []
nintendo_64[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_64] = nintendo_64

###########################################################
# Nintendo DS
###########################################################
nintendo_ds = {}
nintendo_ds[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_ds[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_ds[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_DS
nintendo_ds[keys.platform_key_addons] = []
nintendo_ds[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_ds[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_ds[keys.platform_key_fillonce_json] = []
nintendo_ds[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_DS] = nintendo_ds

###########################################################
# Nintendo DSi
###########################################################
nintendo_dsi = {}
nintendo_dsi[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_dsi[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_dsi[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_DSI
nintendo_dsi[keys.platform_key_addons] = []
nintendo_dsi[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_dsi[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_dsi[keys.platform_key_fillonce_json] = []
nintendo_dsi[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_DSI] = nintendo_dsi

###########################################################
# Nintendo Famicom
###########################################################
nintendo_famicom = {}
nintendo_famicom[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_famicom[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_famicom[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_FAMICOM
nintendo_famicom[keys.platform_key_addons] = []
nintendo_famicom[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_famicom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_famicom[keys.platform_key_fillonce_json] = []
nintendo_famicom[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_FAMICOM] = nintendo_famicom

###########################################################
# Nintendo Game Boy
###########################################################
nintendo_game_boy = {}
nintendo_game_boy[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_game_boy[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_game_boy[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAME_BOY
nintendo_game_boy[keys.platform_key_addons] = []
nintendo_game_boy[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_game_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy[keys.platform_key_fillonce_json] = []
nintendo_game_boy[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_GAME_BOY] = nintendo_game_boy

###########################################################
# Nintendo Game Boy Advance
###########################################################
nintendo_game_boy_advance = {}
nintendo_game_boy_advance[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_game_boy_advance[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_game_boy_advance[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE
nintendo_game_boy_advance[keys.platform_key_addons] = []
nintendo_game_boy_advance[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_game_boy_advance[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_advance[keys.platform_key_fillonce_json] = []
nintendo_game_boy_advance[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_GAME_BOY_ADVANCE] = nintendo_game_boy_advance

###########################################################
# Nintendo Game Boy Advance e-Reader
###########################################################
nintendo_game_boy_advance_ereader = {}
nintendo_game_boy_advance_ereader[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_game_boy_advance_ereader[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_game_boy_advance_ereader[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE_EREADER
nintendo_game_boy_advance_ereader[keys.platform_key_addons] = []
nintendo_game_boy_advance_ereader[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_game_boy_advance_ereader[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_advance_ereader[keys.platform_key_fillonce_json] = []
nintendo_game_boy_advance_ereader[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_GAME_BOY_ADVANCE_EREADER] = nintendo_game_boy_advance_ereader

###########################################################
# Nintendo Game Boy Color
###########################################################
nintendo_game_boy_color = {}
nintendo_game_boy_color[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_game_boy_color[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_game_boy_color[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAME_BOY_COLOR
nintendo_game_boy_color[keys.platform_key_addons] = []
nintendo_game_boy_color[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_game_boy_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_game_boy_color[keys.platform_key_fillonce_json] = []
nintendo_game_boy_color[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_GAME_BOY_COLOR] = nintendo_game_boy_color

###########################################################
# Nintendo Gamecube
###########################################################
nintendo_gamecube = {}
nintendo_gamecube[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_gamecube[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_gamecube[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_GAMECUBE
nintendo_gamecube[keys.platform_key_addons] = []
nintendo_gamecube[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_gamecube[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_gamecube[keys.platform_key_fillonce_json] = []
nintendo_gamecube[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_GAMECUBE] = nintendo_gamecube

###########################################################
# Nintendo NES
###########################################################
nintendo_nes = {}
nintendo_nes[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_nes[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_nes[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_NES
nintendo_nes[keys.platform_key_addons] = []
nintendo_nes[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_nes[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_nes[keys.platform_key_fillonce_json] = []
nintendo_nes[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_NES] = nintendo_nes

###########################################################
# Nintendo SNES
###########################################################
nintendo_snes = {}
nintendo_snes[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_snes[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_snes[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SNES
nintendo_snes[keys.platform_key_addons] = []
nintendo_snes[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_snes[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_snes[keys.platform_key_fillonce_json] = []
nintendo_snes[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_SNES] = nintendo_snes

###########################################################
# Nintendo SNES MSU-1
###########################################################
nintendo_snes_msu1 = {}
nintendo_snes_msu1[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_snes_msu1[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_snes_msu1[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SNES_MSU1
nintendo_snes_msu1[keys.platform_key_addons] = []
nintendo_snes_msu1[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_snes_msu1[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_snes_msu1[keys.platform_key_fillonce_json] = []
nintendo_snes_msu1[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_SNES_MSU1] = nintendo_snes_msu1

###########################################################
# Nintendo Super Famicom
###########################################################
nintendo_super_famicom = {}
nintendo_super_famicom[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_super_famicom[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_super_famicom[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SUPER_FAMICOM
nintendo_super_famicom[keys.platform_key_addons] = []
nintendo_super_famicom[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_super_famicom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_famicom[keys.platform_key_fillonce_json] = []
nintendo_super_famicom[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_SUPER_FAMICOM] = nintendo_super_famicom

###########################################################
# Nintendo Super Game Boy
###########################################################
nintendo_super_game_boy = {}
nintendo_super_game_boy[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_super_game_boy[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_super_game_boy[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SUPER_GAME_BOY
nintendo_super_game_boy[keys.platform_key_addons] = []
nintendo_super_game_boy[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_super_game_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_game_boy[keys.platform_key_fillonce_json] = []
nintendo_super_game_boy[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_SUPER_GAME_BOY] = nintendo_super_game_boy

###########################################################
# Nintendo Super Game Boy Color
###########################################################
nintendo_super_game_boy_color = {}
nintendo_super_game_boy_color[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_super_game_boy_color[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_super_game_boy_color[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SUPER_GAME_BOY_COLOR
nintendo_super_game_boy_color[keys.platform_key_addons] = []
nintendo_super_game_boy_color[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_super_game_boy_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_super_game_boy_color[keys.platform_key_fillonce_json] = []
nintendo_super_game_boy_color[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_SUPER_GAME_BOY_COLOR] = nintendo_super_game_boy_color

###########################################################
# Nintendo Switch
###########################################################
nintendo_switch = {}
nintendo_switch[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_switch[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_switch[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SWITCH
nintendo_switch[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
nintendo_switch[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_switch[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_switch[keys.platform_key_fillonce_json] = []
nintendo_switch[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_SWITCH] = nintendo_switch

###########################################################
# Nintendo Switch eShop
###########################################################
nintendo_switch_eshop = {}
nintendo_switch_eshop[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_switch_eshop[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_switch_eshop[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_SWITCH_ESHOP
nintendo_switch_eshop[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
nintendo_switch_eshop[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_switch_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_switch_eshop[keys.platform_key_fillonce_json] = []
nintendo_switch_eshop[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_SWITCH_ESHOP] = nintendo_switch_eshop

###########################################################
# Nintendo Virtual Boy
###########################################################
nintendo_virtual_boy = {}
nintendo_virtual_boy[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_virtual_boy[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_virtual_boy[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_VIRTUAL_BOY
nintendo_virtual_boy[keys.platform_key_addons] = []
nintendo_virtual_boy[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_virtual_boy[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_virtual_boy[keys.platform_key_fillonce_json] = []
nintendo_virtual_boy[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_VIRTUAL_BOY] = nintendo_virtual_boy

###########################################################
# Nintendo Wii
###########################################################
nintendo_wii = {}
nintendo_wii[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_wii[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_wii[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_WII
nintendo_wii[keys.platform_key_addons] = [types.AddonType.DLC]
nintendo_wii[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_wii[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii[keys.platform_key_fillonce_json] = []
nintendo_wii[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_WII] = nintendo_wii

###########################################################
# Nintendo Wii U
###########################################################
nintendo_wii_u = {}
nintendo_wii_u[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_wii_u[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_wii_u[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_WII_U
nintendo_wii_u[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
nintendo_wii_u[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_wii_u[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii_u[keys.platform_key_fillonce_json] = []
nintendo_wii_u[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_WII_U] = nintendo_wii_u

###########################################################
# Nintendo Wii U eShop
###########################################################
nintendo_wii_u_eshop = {}
nintendo_wii_u_eshop[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_wii_u_eshop[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_wii_u_eshop[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_WII_U_ESHOP
nintendo_wii_u_eshop[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
nintendo_wii_u_eshop[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_wii_u_eshop[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wii_u_eshop[keys.platform_key_fillonce_json] = []
nintendo_wii_u_eshop[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_WII_U_ESHOP] = nintendo_wii_u_eshop

###########################################################
# Nintendo WiiWare
###########################################################
nintendo_wiiware = {}
nintendo_wiiware[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nintendo_wiiware[keys.platform_key_category] = categories.Category.NINTENDO
nintendo_wiiware[keys.platform_key_subcategory] = categories.Subcategory.NINTENDO_WIIWARE
nintendo_wiiware[keys.platform_key_addons] = [types.AddonType.DLC]
nintendo_wiiware[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nintendo_wiiware[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nintendo_wiiware[keys.platform_key_fillonce_json] = []
nintendo_wiiware[keys.platform_key_merge_json] = []
platforms[Platform.NINTENDO_WIIWARE] = nintendo_wiiware

######################################################################################

###########################################################
# Apple iOS
###########################################################
apple_ios = {}
apple_ios[keys.platform_key_supercategory] = categories.Supercategory.ROMS
apple_ios[keys.platform_key_category] = categories.Category.OTHER
apple_ios[keys.platform_key_subcategory] = categories.Subcategory.OTHER_APPLE_IOS
apple_ios[keys.platform_key_addons] = []
apple_ios[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER]
apple_ios[keys.platform_key_autofill_json] = [keys.json_key_files]
apple_ios[keys.platform_key_fillonce_json] = []
apple_ios[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_APPLE_IOS] = apple_ios

###########################################################
# Apple MacOS 8
###########################################################
apple_macos_8 = {}
apple_macos_8[keys.platform_key_supercategory] = categories.Supercategory.ROMS
apple_macos_8[keys.platform_key_category] = categories.Category.OTHER
apple_macos_8[keys.platform_key_subcategory] = categories.Subcategory.OTHER_APPLE_MACOS_8
apple_macos_8[keys.platform_key_addons] = []
apple_macos_8[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
apple_macos_8[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
apple_macos_8[keys.platform_key_fillonce_json] = []
apple_macos_8[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_APPLE_MACOS_8] = apple_macos_8

###########################################################
# Arcade
###########################################################
arcade = {}
arcade[keys.platform_key_supercategory] = categories.Supercategory.ROMS
arcade[keys.platform_key_category] = categories.Category.OTHER
arcade[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ARCADE
arcade[keys.platform_key_addons] = []
arcade[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_NAME]
arcade[keys.platform_key_autofill_json] = [keys.json_key_files]
arcade[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
arcade[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_ARCADE] = arcade

###########################################################
# Atari 800
###########################################################
atari_800 = {}
atari_800[keys.platform_key_supercategory] = categories.Supercategory.ROMS
atari_800[keys.platform_key_category] = categories.Category.OTHER
atari_800[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_800
atari_800[keys.platform_key_addons] = []
atari_800[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
atari_800[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_800[keys.platform_key_fillonce_json] = []
atari_800[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_ATARI_800] = atari_800

###########################################################
# Atari 2600
###########################################################
atari_2600 = {}
atari_2600[keys.platform_key_supercategory] = categories.Supercategory.ROMS
atari_2600[keys.platform_key_category] = categories.Category.OTHER
atari_2600[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_2600
atari_2600[keys.platform_key_addons] = []
atari_2600[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
atari_2600[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_2600[keys.platform_key_fillonce_json] = []
atari_2600[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_ATARI_2600] = atari_2600

###########################################################
# Atari 5200
###########################################################
atari_5200 = {}
atari_5200[keys.platform_key_supercategory] = categories.Supercategory.ROMS
atari_5200[keys.platform_key_category] = categories.Category.OTHER
atari_5200[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_5200
atari_5200[keys.platform_key_addons] = []
atari_5200[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
atari_5200[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_5200[keys.platform_key_fillonce_json] = []
atari_5200[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_ATARI_5200] = atari_5200

###########################################################
# Atari 7800
###########################################################
atari_7800 = {}
atari_7800[keys.platform_key_supercategory] = categories.Supercategory.ROMS
atari_7800[keys.platform_key_category] = categories.Category.OTHER
atari_7800[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_7800
atari_7800[keys.platform_key_addons] = []
atari_7800[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
atari_7800[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_7800[keys.platform_key_fillonce_json] = []
atari_7800[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_ATARI_7800] = atari_7800

###########################################################
# Atari Jaguar
###########################################################
atari_jaguar = {}
atari_jaguar[keys.platform_key_supercategory] = categories.Supercategory.ROMS
atari_jaguar[keys.platform_key_category] = categories.Category.OTHER
atari_jaguar[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_JAGUAR
atari_jaguar[keys.platform_key_addons] = []
atari_jaguar[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
atari_jaguar[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_jaguar[keys.platform_key_fillonce_json] = []
atari_jaguar[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_ATARI_JAGUAR] = atari_jaguar

###########################################################
# Atari Jaguar CD
###########################################################
atari_jaguar_cd = {}
atari_jaguar_cd[keys.platform_key_supercategory] = categories.Supercategory.ROMS
atari_jaguar_cd[keys.platform_key_category] = categories.Category.OTHER
atari_jaguar_cd[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_JAGUAR_CD
atari_jaguar_cd[keys.platform_key_addons] = []
atari_jaguar_cd[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
atari_jaguar_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_jaguar_cd[keys.platform_key_fillonce_json] = []
atari_jaguar_cd[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_ATARI_JAGUAR_CD] = atari_jaguar_cd

###########################################################
# Atari Lynx
###########################################################
atari_lynx = {}
atari_lynx[keys.platform_key_supercategory] = categories.Supercategory.ROMS
atari_lynx[keys.platform_key_category] = categories.Category.OTHER
atari_lynx[keys.platform_key_subcategory] = categories.Subcategory.OTHER_ATARI_LYNX
atari_lynx[keys.platform_key_addons] = []
atari_lynx[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
atari_lynx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
atari_lynx[keys.platform_key_fillonce_json] = []
atari_lynx[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_ATARI_LYNX] = atari_lynx

###########################################################
# Bandai WonderSwan
###########################################################
bandai_wonderswan = {}
bandai_wonderswan[keys.platform_key_supercategory] = categories.Supercategory.ROMS
bandai_wonderswan[keys.platform_key_category] = categories.Category.OTHER
bandai_wonderswan[keys.platform_key_subcategory] = categories.Subcategory.OTHER_BANDAI_WONDERSWAN
bandai_wonderswan[keys.platform_key_addons] = []
bandai_wonderswan[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
bandai_wonderswan[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
bandai_wonderswan[keys.platform_key_fillonce_json] = []
bandai_wonderswan[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_BANDAI_WONDERSWAN] = bandai_wonderswan

###########################################################
# Bandai WonderSwan Color
###########################################################
bandai_wonderswan_color = {}
bandai_wonderswan_color[keys.platform_key_supercategory] = categories.Supercategory.ROMS
bandai_wonderswan_color[keys.platform_key_category] = categories.Category.OTHER
bandai_wonderswan_color[keys.platform_key_subcategory] = categories.Subcategory.OTHER_BANDAI_WONDERSWAN_COLOR
bandai_wonderswan_color[keys.platform_key_addons] = []
bandai_wonderswan_color[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
bandai_wonderswan_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
bandai_wonderswan_color[keys.platform_key_fillonce_json] = []
bandai_wonderswan_color[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_BANDAI_WONDERSWAN_COLOR] = bandai_wonderswan_color

###########################################################
# Coleco ColecoVision
###########################################################
coleco_colecovision = {}
coleco_colecovision[keys.platform_key_supercategory] = categories.Supercategory.ROMS
coleco_colecovision[keys.platform_key_category] = categories.Category.OTHER
coleco_colecovision[keys.platform_key_subcategory] = categories.Subcategory.OTHER_COLECO_COLECOVISION
coleco_colecovision[keys.platform_key_addons] = []
coleco_colecovision[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
coleco_colecovision[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
coleco_colecovision[keys.platform_key_fillonce_json] = []
coleco_colecovision[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_COLECO_COLECOVISION] = coleco_colecovision

###########################################################
# Commodore 64
###########################################################
commodore_64 = {}
commodore_64[keys.platform_key_supercategory] = categories.Supercategory.ROMS
commodore_64[keys.platform_key_category] = categories.Category.OTHER
commodore_64[keys.platform_key_subcategory] = categories.Subcategory.OTHER_COMMODORE_64
commodore_64[keys.platform_key_addons] = []
commodore_64[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
commodore_64[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
commodore_64[keys.platform_key_fillonce_json] = []
commodore_64[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_COMMODORE_64] = commodore_64

###########################################################
# Commodore Amiga
###########################################################
commodore_amiga = {}
commodore_amiga[keys.platform_key_supercategory] = categories.Supercategory.ROMS
commodore_amiga[keys.platform_key_category] = categories.Category.OTHER
commodore_amiga[keys.platform_key_subcategory] = categories.Subcategory.OTHER_COMMODORE_AMIGA
commodore_amiga[keys.platform_key_addons] = []
commodore_amiga[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
commodore_amiga[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
commodore_amiga[keys.platform_key_fillonce_json] = []
commodore_amiga[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_COMMODORE_AMIGA] = commodore_amiga

###########################################################
# Google Android
###########################################################
google_android = {}
google_android[keys.platform_key_supercategory] = categories.Supercategory.ROMS
google_android[keys.platform_key_category] = categories.Category.OTHER
google_android[keys.platform_key_subcategory] = categories.Subcategory.OTHER_GOOGLE_ANDROID
google_android[keys.platform_key_addons] = []
google_android[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER]
google_android[keys.platform_key_autofill_json] = [keys.json_key_files]
google_android[keys.platform_key_fillonce_json] = []
google_android[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_GOOGLE_ANDROID] = google_android

###########################################################
# Magnavox Odyssey 2
###########################################################
magnavox_odyssey_2 = {}
magnavox_odyssey_2[keys.platform_key_supercategory] = categories.Supercategory.ROMS
magnavox_odyssey_2[keys.platform_key_category] = categories.Category.OTHER
magnavox_odyssey_2[keys.platform_key_subcategory] = categories.Subcategory.OTHER_MAGNAVOX_ODYSSEY_2
magnavox_odyssey_2[keys.platform_key_addons] = []
magnavox_odyssey_2[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
magnavox_odyssey_2[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
magnavox_odyssey_2[keys.platform_key_fillonce_json] = []
magnavox_odyssey_2[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_MAGNAVOX_ODYSSEY_2] = magnavox_odyssey_2

###########################################################
# Mattel Intellivision
###########################################################
mattel_intellivision = {}
mattel_intellivision[keys.platform_key_supercategory] = categories.Supercategory.ROMS
mattel_intellivision[keys.platform_key_category] = categories.Category.OTHER
mattel_intellivision[keys.platform_key_subcategory] = categories.Subcategory.OTHER_MATTEL_INTELLIVISION
mattel_intellivision[keys.platform_key_addons] = []
mattel_intellivision[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
mattel_intellivision[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
mattel_intellivision[keys.platform_key_fillonce_json] = []
mattel_intellivision[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_MATTEL_INTELLIVISION] = mattel_intellivision

###########################################################
# NEC PC-Engine
###########################################################
nec_pcengine = {}
nec_pcengine[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nec_pcengine[keys.platform_key_category] = categories.Category.OTHER
nec_pcengine[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_PCENGINE
nec_pcengine[keys.platform_key_addons] = []
nec_pcengine[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nec_pcengine[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_pcengine[keys.platform_key_fillonce_json] = []
nec_pcengine[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_NEC_PCENGINE] = nec_pcengine

###########################################################
# NEC PC-Engine CD
###########################################################
nec_pcengine_cd = {}
nec_pcengine_cd[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nec_pcengine_cd[keys.platform_key_category] = categories.Category.OTHER
nec_pcengine_cd[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_PCENGINE_CD
nec_pcengine_cd[keys.platform_key_addons] = []
nec_pcengine_cd[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nec_pcengine_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_pcengine_cd[keys.platform_key_fillonce_json] = []
nec_pcengine_cd[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_NEC_PCENGINE_CD] = nec_pcengine_cd

###########################################################
# NEC SuperGrafx
###########################################################
nec_supergrafx = {}
nec_supergrafx[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nec_supergrafx[keys.platform_key_category] = categories.Category.OTHER
nec_supergrafx[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_SUPERGRAFX
nec_supergrafx[keys.platform_key_addons] = []
nec_supergrafx[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nec_supergrafx[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_supergrafx[keys.platform_key_fillonce_json] = []
nec_supergrafx[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_NEC_SUPERGRAFX] = nec_supergrafx

###########################################################
# NEC TurboGrafx-16
###########################################################
nec_turbografx_16 = {}
nec_turbografx_16[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nec_turbografx_16[keys.platform_key_category] = categories.Category.OTHER
nec_turbografx_16[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_TURBOGRAFX_16
nec_turbografx_16[keys.platform_key_addons] = []
nec_turbografx_16[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nec_turbografx_16[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_turbografx_16[keys.platform_key_fillonce_json] = []
nec_turbografx_16[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_NEC_TURBOGRAFX_16] = nec_turbografx_16

###########################################################
# NEC TurboGrafx CD
###########################################################
nec_turbografx_cd = {}
nec_turbografx_cd[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nec_turbografx_cd[keys.platform_key_category] = categories.Category.OTHER
nec_turbografx_cd[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NEC_TURBOGRAFX_CD
nec_turbografx_cd[keys.platform_key_addons] = []
nec_turbografx_cd[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
nec_turbografx_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
nec_turbografx_cd[keys.platform_key_fillonce_json] = []
nec_turbografx_cd[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_NEC_TURBOGRAFX_CD] = nec_turbografx_cd

###########################################################
# Nokia N-Gage
###########################################################
nokia_ngage = {}
nokia_ngage[keys.platform_key_supercategory] = categories.Supercategory.ROMS
nokia_ngage[keys.platform_key_category] = categories.Category.OTHER
nokia_ngage[keys.platform_key_subcategory] = categories.Subcategory.OTHER_NOKIA_NGAGE
nokia_ngage[keys.platform_key_addons] = []
nokia_ngage[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_NAME]
nokia_ngage[keys.platform_key_autofill_json] = [keys.json_key_files]
nokia_ngage[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
nokia_ngage[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_NOKIA_NGAGE] = nokia_ngage

###########################################################
# Panasonic 3DO
###########################################################
panasonic_3do = {}
panasonic_3do[keys.platform_key_supercategory] = categories.Supercategory.ROMS
panasonic_3do[keys.platform_key_category] = categories.Category.OTHER
panasonic_3do[keys.platform_key_subcategory] = categories.Subcategory.OTHER_PANASONIC_3DO
panasonic_3do[keys.platform_key_addons] = []
panasonic_3do[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
panasonic_3do[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
panasonic_3do[keys.platform_key_fillonce_json] = []
panasonic_3do[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_PANASONIC_3DO] = panasonic_3do

###########################################################
# Philips CDi
###########################################################
philips_cdi = {}
philips_cdi[keys.platform_key_supercategory] = categories.Supercategory.ROMS
philips_cdi[keys.platform_key_category] = categories.Category.OTHER
philips_cdi[keys.platform_key_subcategory] = categories.Subcategory.OTHER_PHILIPS_CDI
philips_cdi[keys.platform_key_addons] = []
philips_cdi[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
philips_cdi[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
philips_cdi[keys.platform_key_fillonce_json] = []
philips_cdi[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_PHILIPS_CDI] = philips_cdi

###########################################################
# SNK Neo Geo Pocket Color
###########################################################
snk_neogeo_pocket_color = {}
snk_neogeo_pocket_color[keys.platform_key_supercategory] = categories.Supercategory.ROMS
snk_neogeo_pocket_color[keys.platform_key_category] = categories.Category.OTHER
snk_neogeo_pocket_color[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SNK_NEOGEO_POCKET_COLOR
snk_neogeo_pocket_color[keys.platform_key_addons] = []
snk_neogeo_pocket_color[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
snk_neogeo_pocket_color[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
snk_neogeo_pocket_color[keys.platform_key_fillonce_json] = []
snk_neogeo_pocket_color[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SNK_NEOGEO_POCKET_COLOR] = snk_neogeo_pocket_color

###########################################################
# Sega 32X
###########################################################
sega_32x = {}
sega_32x[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sega_32x[keys.platform_key_category] = categories.Category.OTHER
sega_32x[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_32X
sega_32x[keys.platform_key_addons] = []
sega_32x[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sega_32x[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_32x[keys.platform_key_fillonce_json] = []
sega_32x[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SEGA_32X] = sega_32x

###########################################################
# Sega CD
###########################################################
sega_cd = {}
sega_cd[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sega_cd[keys.platform_key_category] = categories.Category.OTHER
sega_cd[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_CD
sega_cd[keys.platform_key_addons] = []
sega_cd[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sega_cd[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_cd[keys.platform_key_fillonce_json] = []
sega_cd[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SEGA_CD] = sega_cd

###########################################################
# Sega CD 32X
###########################################################
sega_cd_32x = {}
sega_cd_32x[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sega_cd_32x[keys.platform_key_category] = categories.Category.OTHER
sega_cd_32x[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_CD_32X
sega_cd_32x[keys.platform_key_addons] = []
sega_cd_32x[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sega_cd_32x[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_cd_32x[keys.platform_key_fillonce_json] = []
sega_cd_32x[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SEGA_CD_32X] = sega_cd_32x

###########################################################
# Sega Dreamcast
###########################################################
sega_dreamcast = {}
sega_dreamcast[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sega_dreamcast[keys.platform_key_category] = categories.Category.OTHER
sega_dreamcast[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_DREAMCAST
sega_dreamcast[keys.platform_key_addons] = []
sega_dreamcast[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sega_dreamcast[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_dreamcast[keys.platform_key_fillonce_json] = []
sega_dreamcast[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SEGA_DREAMCAST] = sega_dreamcast

###########################################################
# Sega Game Gear
###########################################################
sega_game_gear = {}
sega_game_gear[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sega_game_gear[keys.platform_key_category] = categories.Category.OTHER
sega_game_gear[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_GAME_GEAR
sega_game_gear[keys.platform_key_addons] = []
sega_game_gear[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sega_game_gear[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_game_gear[keys.platform_key_fillonce_json] = []
sega_game_gear[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SEGA_GAME_GEAR] = sega_game_gear

###########################################################
# Sega Genesis
###########################################################
sega_genesis = {}
sega_genesis[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sega_genesis[keys.platform_key_category] = categories.Category.OTHER
sega_genesis[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_GENESIS
sega_genesis[keys.platform_key_addons] = []
sega_genesis[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sega_genesis[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_genesis[keys.platform_key_fillonce_json] = []
sega_genesis[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SEGA_GENESIS] = sega_genesis

###########################################################
# Sega Master System
###########################################################
sega_master_system = {}
sega_master_system[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sega_master_system[keys.platform_key_category] = categories.Category.OTHER
sega_master_system[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_MASTER_SYSTEM
sega_master_system[keys.platform_key_addons] = []
sega_master_system[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sega_master_system[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_master_system[keys.platform_key_fillonce_json] = []
sega_master_system[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SEGA_MASTER_SYSTEM] = sega_master_system

###########################################################
# Sega Saturn
###########################################################
sega_saturn = {}
sega_saturn[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sega_saturn[keys.platform_key_category] = categories.Category.OTHER
sega_saturn[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SEGA_SATURN
sega_saturn[keys.platform_key_addons] = []
sega_saturn[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sega_saturn[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sega_saturn[keys.platform_key_fillonce_json] = []
sega_saturn[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SEGA_SATURN] = sega_saturn

###########################################################
# Sinclair ZX Spectrum
###########################################################
sinclair_zx_spectrum = {}
sinclair_zx_spectrum[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sinclair_zx_spectrum[keys.platform_key_category] = categories.Category.OTHER
sinclair_zx_spectrum[keys.platform_key_subcategory] = categories.Subcategory.OTHER_SINCLAIR_ZX_SPECTRUM
sinclair_zx_spectrum[keys.platform_key_addons] = []
sinclair_zx_spectrum[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sinclair_zx_spectrum[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sinclair_zx_spectrum[keys.platform_key_fillonce_json] = []
sinclair_zx_spectrum[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_SINCLAIR_ZX_SPECTRUM] = sinclair_zx_spectrum

###########################################################
# Texas Instruments TI-99-4A
###########################################################
texas_instruments_ti994a = {}
texas_instruments_ti994a[keys.platform_key_supercategory] = categories.Supercategory.ROMS
texas_instruments_ti994a[keys.platform_key_category] = categories.Category.OTHER
texas_instruments_ti994a[keys.platform_key_subcategory] = categories.Subcategory.OTHER_TEXAS_INSTRUMENTS_TI994A
texas_instruments_ti994a[keys.platform_key_addons] = []
texas_instruments_ti994a[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
texas_instruments_ti994a[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
texas_instruments_ti994a[keys.platform_key_fillonce_json] = []
texas_instruments_ti994a[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_TEXAS_INSTRUMENTS_TI994A] = texas_instruments_ti994a

###########################################################
# Tiger Game.com
###########################################################
tiger_gamecom = {}
tiger_gamecom[keys.platform_key_supercategory] = categories.Supercategory.ROMS
tiger_gamecom[keys.platform_key_category] = categories.Category.OTHER
tiger_gamecom[keys.platform_key_subcategory] = categories.Subcategory.OTHER_TIGER_GAMECOM
tiger_gamecom[keys.platform_key_addons] = []
tiger_gamecom[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
tiger_gamecom[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
tiger_gamecom[keys.platform_key_fillonce_json] = []
tiger_gamecom[keys.platform_key_merge_json] = []
platforms[Platform.OTHER_TIGER_GAMECOM] = tiger_gamecom

######################################################################################

###########################################################
# Sony PlayStation
###########################################################
sony_playstation = {}
sony_playstation[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation[keys.platform_key_category] = categories.Category.SONY
sony_playstation[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION
sony_playstation[keys.platform_key_addons] = []
sony_playstation[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sony_playstation[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation[keys.platform_key_fillonce_json] = []
sony_playstation[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION] = sony_playstation

###########################################################
# Sony PlayStation 2
###########################################################
sony_playstation_2 = {}
sony_playstation_2[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_2[keys.platform_key_category] = categories.Category.SONY
sony_playstation_2[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_2
sony_playstation_2[keys.platform_key_addons] = []
sony_playstation_2[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sony_playstation_2[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_2[keys.platform_key_fillonce_json] = []
sony_playstation_2[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_2] = sony_playstation_2

###########################################################
# Sony PlayStation 3
###########################################################
sony_playstation_3 = {}
sony_playstation_3[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_3[keys.platform_key_category] = categories.Category.SONY
sony_playstation_3[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_3
sony_playstation_3[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
sony_playstation_3[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sony_playstation_3[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_3[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
sony_playstation_3[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_3] = sony_playstation_3

###########################################################
# Sony PlayStation 4
###########################################################
sony_playstation_4 = {}
sony_playstation_4[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_4[keys.platform_key_category] = categories.Category.SONY
sony_playstation_4[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_4
sony_playstation_4[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
sony_playstation_4[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER]
sony_playstation_4[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_4[keys.platform_key_fillonce_json] = []
sony_playstation_4[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_4] = sony_playstation_4

###########################################################
# Sony PlayStation Network - PlayStation 3
###########################################################
sony_playstation_network_ps3 = {}
sony_playstation_network_ps3[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_network_ps3[keys.platform_key_category] = categories.Category.SONY
sony_playstation_network_ps3[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS3
sony_playstation_network_ps3[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
sony_playstation_network_ps3[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sony_playstation_network_ps3[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_network_ps3[keys.platform_key_fillonce_json] = [keys.json_key_launch_file]
sony_playstation_network_ps3[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_NETWORK_PS3] = sony_playstation_network_ps3

###########################################################
# Sony PlayStation Network - PlayStation 4
###########################################################
sony_playstation_network_ps4 = {}
sony_playstation_network_ps4[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_network_ps4[keys.platform_key_category] = categories.Category.SONY
sony_playstation_network_ps4[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS4
sony_playstation_network_ps4[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
sony_playstation_network_ps4[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER]
sony_playstation_network_ps4[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_network_ps4[keys.platform_key_fillonce_json] = []
sony_playstation_network_ps4[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_NETWORK_PS4] = sony_playstation_network_ps4

###########################################################
# Sony PlayStation Network - PlayStation Portable
###########################################################
sony_playstation_network_psp = {}
sony_playstation_network_psp[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_network_psp[keys.platform_key_category] = categories.Category.SONY
sony_playstation_network_psp[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSP
sony_playstation_network_psp[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
sony_playstation_network_psp[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sony_playstation_network_psp[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_network_psp[keys.platform_key_fillonce_json] = []
sony_playstation_network_psp[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_NETWORK_PSP] = sony_playstation_network_psp

###########################################################
# Sony PlayStation Network - PlayStation Portable Minis
###########################################################
sony_playstation_network_pspm = {}
sony_playstation_network_pspm[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_network_pspm[keys.platform_key_category] = categories.Category.SONY
sony_playstation_network_pspm[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSPM
sony_playstation_network_pspm[keys.platform_key_addons] = []
sony_playstation_network_pspm[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sony_playstation_network_pspm[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_network_pspm[keys.platform_key_fillonce_json] = []
sony_playstation_network_pspm[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_NETWORK_PSPM] = sony_playstation_network_pspm

###########################################################
# Sony PlayStation Network - PlayStation Vita
###########################################################
sony_playstation_network_psv = {}
sony_playstation_network_psv[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_network_psv[keys.platform_key_category] = categories.Category.SONY
sony_playstation_network_psv[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSV
sony_playstation_network_psv[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
sony_playstation_network_psv[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_NAME]
sony_playstation_network_psv[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_transform_file]
sony_playstation_network_psv[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
sony_playstation_network_psv[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_NETWORK_PSV] = sony_playstation_network_psv

###########################################################
# Sony PlayStation Portable
###########################################################
sony_playstation_portable = {}
sony_playstation_portable[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_portable[keys.platform_key_category] = categories.Category.SONY
sony_playstation_portable[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_PORTABLE
sony_playstation_portable[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
sony_playstation_portable[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_FILE]
sony_playstation_portable[keys.platform_key_autofill_json] = [keys.json_key_files, keys.json_key_launch_file]
sony_playstation_portable[keys.platform_key_fillonce_json] = []
sony_playstation_portable[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_PORTABLE] = sony_playstation_portable

###########################################################
# Sony PlayStation Portable Video
###########################################################
sony_playstation_portable_video = {}
sony_playstation_portable_video[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_portable_video[keys.platform_key_category] = categories.Category.SONY
sony_playstation_portable_video[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_PORTABLE_VIDEO
sony_playstation_portable_video[keys.platform_key_addons] = []
sony_playstation_portable_video[keys.platform_key_launcher] = [types.LaunchType.NO_LAUNCHER]
sony_playstation_portable_video[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_portable_video[keys.platform_key_fillonce_json] = []
sony_playstation_portable_video[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_PORTABLE_VIDEO] = sony_playstation_portable_video

###########################################################
# Sony PlayStation Vita
###########################################################
sony_playstation_vita = {}
sony_playstation_vita[keys.platform_key_supercategory] = categories.Supercategory.ROMS
sony_playstation_vita[keys.platform_key_category] = categories.Category.SONY
sony_playstation_vita[keys.platform_key_subcategory] = categories.Subcategory.SONY_PLAYSTATION_VITA
sony_playstation_vita[keys.platform_key_addons] = [types.AddonType.DLC, types.AddonType.UPDATES]
sony_playstation_vita[keys.platform_key_launcher] = [types.LaunchType.LAUNCH_NAME]
sony_playstation_vita[keys.platform_key_autofill_json] = [keys.json_key_files]
sony_playstation_vita[keys.platform_key_fillonce_json] = [keys.json_key_launch_name]
sony_playstation_vita[keys.platform_key_merge_json] = []
platforms[Platform.SONY_PLAYSTATION_VITA] = sony_playstation_vita
