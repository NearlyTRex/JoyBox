# Local imports
from . import categories
from . import keys
from . import types

# Platforms
class Platform(types.EnumType):

    # Computer
    COMPUTER_AMAZON_GAMES               = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_AMAZON_GAMES
    COMPUTER_DISC                       = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_DISC
    COMPUTER_EPIC_GAMES                 = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_EPIC_GAMES
    COMPUTER_GOG                        = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_GOG
    COMPUTER_HUMBLE_BUNDLE              = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_HUMBLE_BUNDLE
    COMPUTER_ITCHIO                     = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_ITCHIO
    COMPUTER_LEGACY_GAMES               = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_LEGACY_GAMES
    COMPUTER_PUPPET_COMBO               = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_PUPPET_COMBO
    COMPUTER_RED_CANDLE                 = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_RED_CANDLE
    COMPUTER_SQUARE_ENIX                = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_SQUARE_ENIX
    COMPUTER_STEAM                      = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_STEAM
    COMPUTER_ZOOM                       = categories.Category.COMPUTER + " - " + categories.Subcategory.COMPUTER_ZOOM

    # Microsoft
    MICROSOFT_MSX                       = categories.Subcategory.MICROSOFT_MSX.val()
    MICROSOFT_XBOX                      = categories.Subcategory.MICROSOFT_XBOX.val()
    MICROSOFT_XBOX_360                  = categories.Subcategory.MICROSOFT_XBOX_360.val()
    MICROSOFT_XBOX_360_GOD              = categories.Subcategory.MICROSOFT_XBOX_360_GOD.val()
    MICROSOFT_XBOX_360_XBLA             = categories.Subcategory.MICROSOFT_XBOX_360_XBLA.val()
    MICROSOFT_XBOX_360_XIG              = categories.Subcategory.MICROSOFT_XBOX_360_XIG.val()
    MICROSOFT_XBOX_ONE                  = categories.Subcategory.MICROSOFT_XBOX_ONE.val()
    MICROSOFT_XBOX_ONE_GOD              = categories.Subcategory.MICROSOFT_XBOX_ONE_GOD.val()

    # Nintendo
    NINTENDO_3DS                        = categories.Subcategory.NINTENDO_3DS.val()
    NINTENDO_3DS_APPS                   = categories.Subcategory.NINTENDO_3DS_APPS.val()
    NINTENDO_3DS_ESHOP                  = categories.Subcategory.NINTENDO_3DS_ESHOP.val()
    NINTENDO_64                         = categories.Subcategory.NINTENDO_64.val()
    NINTENDO_AMIIBO                     = categories.Subcategory.NINTENDO_AMIIBO.val()
    NINTENDO_DS                         = categories.Subcategory.NINTENDO_DS.val()
    NINTENDO_DSI                        = categories.Subcategory.NINTENDO_DSI.val()
    NINTENDO_FAMICOM                    = categories.Subcategory.NINTENDO_FAMICOM.val()
    NINTENDO_GAME_BOY                   = categories.Subcategory.NINTENDO_GAME_BOY.val()
    NINTENDO_GAME_BOY_ADVANCE           = categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE.val()
    NINTENDO_GAME_BOY_ADVANCE_EREADER   = categories.Subcategory.NINTENDO_GAME_BOY_ADVANCE_EREADER.val()
    NINTENDO_GAME_BOY_COLOR             = categories.Subcategory.NINTENDO_GAME_BOY_COLOR.val()
    NINTENDO_GAMECUBE                   = categories.Subcategory.NINTENDO_GAMECUBE.val()
    NINTENDO_NES                        = categories.Subcategory.NINTENDO_NES.val()
    NINTENDO_SNES                       = categories.Subcategory.NINTENDO_SNES.val()
    NINTENDO_SNES_MSU1                  = categories.Subcategory.NINTENDO_SNES_MSU1.val()
    NINTENDO_SUPER_FAMICOM              = categories.Subcategory.NINTENDO_SUPER_FAMICOM.val()
    NINTENDO_SUPER_GAME_BOY             = categories.Subcategory.NINTENDO_SUPER_GAME_BOY.val()
    NINTENDO_SUPER_GAME_BOY_COLOR       = categories.Subcategory.NINTENDO_SUPER_GAME_BOY_COLOR.val()
    NINTENDO_SWITCH                     = categories.Subcategory.NINTENDO_SWITCH.val()
    NINTENDO_SWITCH_ESHOP               = categories.Subcategory.NINTENDO_SWITCH_ESHOP.val()
    NINTENDO_VIRTUAL_BOY                = categories.Subcategory.NINTENDO_VIRTUAL_BOY.val()
    NINTENDO_WII                        = categories.Subcategory.NINTENDO_WII.val()
    NINTENDO_WII_U                      = categories.Subcategory.NINTENDO_WII_U.val()
    NINTENDO_WII_U_ESHOP                = categories.Subcategory.NINTENDO_WII_U_ESHOP.val()
    NINTENDO_WIIWARE                    = categories.Subcategory.NINTENDO_WIIWARE.val()

    # Other
    OTHER_APPLE_IOS                     = categories.Subcategory.OTHER_APPLE_IOS.val()
    OTHER_APPLE_MACOS_8                 = categories.Subcategory.OTHER_APPLE_MACOS_8.val()
    OTHER_ARCADE                        = categories.Subcategory.OTHER_ARCADE.val()
    OTHER_ATARI_800                     = categories.Subcategory.OTHER_ATARI_800.val()
    OTHER_ATARI_2600                    = categories.Subcategory.OTHER_ATARI_2600.val()
    OTHER_ATARI_5200                    = categories.Subcategory.OTHER_ATARI_5200.val()
    OTHER_ATARI_7800                    = categories.Subcategory.OTHER_ATARI_7800.val()
    OTHER_ATARI_JAGUAR                  = categories.Subcategory.OTHER_ATARI_JAGUAR.val()
    OTHER_ATARI_JAGUAR_CD               = categories.Subcategory.OTHER_ATARI_JAGUAR_CD.val()
    OTHER_ATARI_LYNX                    = categories.Subcategory.OTHER_ATARI_LYNX.val()
    OTHER_BANDAI_WONDERSWAN             = categories.Subcategory.OTHER_BANDAI_WONDERSWAN.val()
    OTHER_BANDAI_WONDERSWAN_COLOR       = categories.Subcategory.OTHER_BANDAI_WONDERSWAN_COLOR.val()
    OTHER_COLECO_COLECOVISION           = categories.Subcategory.OTHER_COLECO_COLECOVISION.val()
    OTHER_COMMODORE_64                  = categories.Subcategory.OTHER_COMMODORE_64.val()
    OTHER_COMMODORE_AMIGA               = categories.Subcategory.OTHER_COMMODORE_AMIGA.val()
    OTHER_GOOGLE_ANDROID                = categories.Subcategory.OTHER_GOOGLE_ANDROID.val()
    OTHER_MAGNAVOX_ODYSSEY_2            = categories.Subcategory.OTHER_MAGNAVOX_ODYSSEY_2.val()
    OTHER_MATTEL_INTELLIVISION          = categories.Subcategory.OTHER_MATTEL_INTELLIVISION.val()
    OTHER_NEC_PCENGINE                  = categories.Subcategory.OTHER_NEC_PCENGINE.val()
    OTHER_NEC_PCENGINE_CD               = categories.Subcategory.OTHER_NEC_PCENGINE_CD.val()
    OTHER_NEC_SUPERGRAFX                = categories.Subcategory.OTHER_NEC_SUPERGRAFX.val()
    OTHER_NEC_TURBOGRAFX_16             = categories.Subcategory.OTHER_NEC_TURBOGRAFX_16.val()
    OTHER_NEC_TURBOGRAFX_CD             = categories.Subcategory.OTHER_NEC_TURBOGRAFX_CD.val()
    OTHER_NOKIA_NGAGE                   = categories.Subcategory.OTHER_NOKIA_NGAGE.val()
    OTHER_PANASONIC_3DO                 = categories.Subcategory.OTHER_PANASONIC_3DO.val()
    OTHER_PHILIPS_CDI                   = categories.Subcategory.OTHER_PHILIPS_CDI.val()
    OTHER_SNK_NEOGEO_POCKET_COLOR       = categories.Subcategory.OTHER_SNK_NEOGEO_POCKET_COLOR.val()
    OTHER_SEGA_32X                      = categories.Subcategory.OTHER_SEGA_32X.val()
    OTHER_SEGA_CD                       = categories.Subcategory.OTHER_SEGA_CD.val()
    OTHER_SEGA_CD_32X                   = categories.Subcategory.OTHER_SEGA_CD_32X.val()
    OTHER_SEGA_DREAMCAST                = categories.Subcategory.OTHER_SEGA_DREAMCAST.val()
    OTHER_SEGA_GAME_GEAR                = categories.Subcategory.OTHER_SEGA_GAME_GEAR.val()
    OTHER_SEGA_GENESIS                  = categories.Subcategory.OTHER_SEGA_GENESIS.val()
    OTHER_SEGA_MASTER_SYSTEM            = categories.Subcategory.OTHER_SEGA_MASTER_SYSTEM.val()
    OTHER_SEGA_SATURN                   = categories.Subcategory.OTHER_SEGA_SATURN.val()
    OTHER_SINCLAIR_ZX_SPECTRUM          = categories.Subcategory.OTHER_SINCLAIR_ZX_SPECTRUM.val()
    OTHER_TEXAS_INSTRUMENTS_TI994A      = categories.Subcategory.OTHER_TEXAS_INSTRUMENTS_TI994A.val()
    OTHER_TIGER_GAMECOM                 = categories.Subcategory.OTHER_TIGER_GAMECOM.val()

    # Sony
    SONY_PLAYSTATION                    = categories.Subcategory.SONY_PLAYSTATION.val()
    SONY_PLAYSTATION_2                  = categories.Subcategory.SONY_PLAYSTATION_2.val()
    SONY_PLAYSTATION_3                  = categories.Subcategory.SONY_PLAYSTATION_3.val()
    SONY_PLAYSTATION_4                  = categories.Subcategory.SONY_PLAYSTATION_4.val()
    SONY_PLAYSTATION_NETWORK_PS3        = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS3.val()
    SONY_PLAYSTATION_NETWORK_PS4        = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PS4.val()
    SONY_PLAYSTATION_NETWORK_PSP        = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSP.val()
    SONY_PLAYSTATION_NETWORK_PSPM       = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSPM.val()
    SONY_PLAYSTATION_NETWORK_PSV        = categories.Subcategory.SONY_PLAYSTATION_NETWORK_PSV.val()
    SONY_PLAYSTATION_PORTABLE           = categories.Subcategory.SONY_PLAYSTATION_PORTABLE.val()
    SONY_PLAYSTATION_PORTABLE_VIDEO     = categories.Subcategory.SONY_PLAYSTATION_PORTABLE_VIDEO.val()
    SONY_PLAYSTATION_VITA               = categories.Subcategory.SONY_PLAYSTATION_VITA.val()

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

# Manual import platforms
manual_import_platforms = [

    # Computer
    Platform.COMPUTER_DISC,
    Platform.COMPUTER_PUPPET_COMBO,
    Platform.COMPUTER_RED_CANDLE,
    Platform.COMPUTER_SQUARE_ENIX,
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

# Add platform section, under the subcategory sharing the platform's name
def add_platform(
    platform,
    category,
    launcher,
    addons = (),
    autofill = (keys.json_key_files,),
    fillonce = (),
    merge = ()):
    platforms[platform] = {
        keys.platform_key_supercategory: categories.Supercategory.ROMS,
        keys.platform_key_category: category,
        keys.platform_key_subcategory: categories.Subcategory[platform.name],
        keys.platform_key_addons: list(addons),
        keys.platform_key_launcher: [launcher],
        keys.platform_key_autofill_json: list(autofill),
        keys.platform_key_fillonce_json: list(fillonce),
        keys.platform_key_merge_json: list(merge)
    }

# Add computer platform section, merging its store's json key
def add_computer_platform(platform, store_key):
    add_platform(
        platform,
        categories.Category.COMPUTER,
        types.LaunchType.LAUNCH_FILE,
        autofill = json_keys_autofill_computer,
        fillonce = json_keys_fillonce_computer,
        merge = json_keys_merge_computer + [store_key])

# Computer - Amazon Games
add_computer_platform(Platform.COMPUTER_AMAZON_GAMES, keys.json_key_amazon)

# Computer - Disc
add_computer_platform(Platform.COMPUTER_DISC, keys.json_key_disc)

# Computer - Epic Games
add_computer_platform(Platform.COMPUTER_EPIC_GAMES, keys.json_key_epic)

# Computer - GOG
add_computer_platform(Platform.COMPUTER_GOG, keys.json_key_gog)

# Computer - Humble Bundle
add_computer_platform(Platform.COMPUTER_HUMBLE_BUNDLE, keys.json_key_humble)

# Computer - Itchio
add_computer_platform(Platform.COMPUTER_ITCHIO, keys.json_key_itchio)

# Computer - Legacy Games
add_computer_platform(Platform.COMPUTER_LEGACY_GAMES, keys.json_key_legacy)

# Computer - Puppet Combo
add_computer_platform(Platform.COMPUTER_PUPPET_COMBO, keys.json_key_puppetcombo)

# Computer - Red Candle
add_computer_platform(Platform.COMPUTER_RED_CANDLE, keys.json_key_redcandle)

# Computer - Square Enix
add_computer_platform(Platform.COMPUTER_SQUARE_ENIX, keys.json_key_squareenix)

# Computer - Steam
add_computer_platform(Platform.COMPUTER_STEAM, keys.json_key_steam)

# Computer - Zoom
add_computer_platform(Platform.COMPUTER_ZOOM, keys.json_key_zoom)

# Microsoft MSX
add_platform(
    Platform.MICROSOFT_MSX,
    categories.Category.MICROSOFT,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Microsoft Xbox
add_platform(
    Platform.MICROSOFT_XBOX,
    categories.Category.MICROSOFT,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_transform_file],
    fillonce = [keys.json_key_launch_file])

# Microsoft Xbox 360
add_platform(
    Platform.MICROSOFT_XBOX_360,
    categories.Category.MICROSOFT,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_transform_file],
    fillonce = [keys.json_key_launch_file])

# Microsoft Xbox 360 GOD
add_platform(
    Platform.MICROSOFT_XBOX_360_GOD,
    categories.Category.MICROSOFT,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    fillonce = [keys.json_key_launch_file])

# Microsoft Xbox 360 XBLA
add_platform(
    Platform.MICROSOFT_XBOX_360_XBLA,
    categories.Category.MICROSOFT,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    fillonce = [keys.json_key_launch_file])

# Microsoft Xbox 360 XIG
add_platform(
    Platform.MICROSOFT_XBOX_360_XIG,
    categories.Category.MICROSOFT,
    types.LaunchType.LAUNCH_FILE,
    fillonce = [keys.json_key_launch_file])

# Microsoft Xbox One
add_platform(
    Platform.MICROSOFT_XBOX_ONE,
    categories.Category.MICROSOFT,
    types.LaunchType.NO_LAUNCHER)

# Microsoft Xbox One GOD
add_platform(
    Platform.MICROSOFT_XBOX_ONE_GOD,
    categories.Category.MICROSOFT,
    types.LaunchType.NO_LAUNCHER)

# Nintendo 3DS
add_platform(
    Platform.NINTENDO_3DS,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo 3DS Apps
add_platform(
    Platform.NINTENDO_3DS_APPS,
    categories.Category.NINTENDO,
    types.LaunchType.NO_LAUNCHER)

# Nintendo 3DS eShop
add_platform(
    Platform.NINTENDO_3DS_ESHOP,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo 64
add_platform(
    Platform.NINTENDO_64,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Amiibo
add_platform(
    Platform.NINTENDO_AMIIBO,
    categories.Category.NINTENDO,
    types.LaunchType.NO_LAUNCHER,
    addons = [types.AddonType.DLC])

# Nintendo DS
add_platform(
    Platform.NINTENDO_DS,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo DSi
add_platform(
    Platform.NINTENDO_DSI,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Famicom
add_platform(
    Platform.NINTENDO_FAMICOM,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Game Boy
add_platform(
    Platform.NINTENDO_GAME_BOY,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Game Boy Advance
add_platform(
    Platform.NINTENDO_GAME_BOY_ADVANCE,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Game Boy Advance e-Reader
add_platform(
    Platform.NINTENDO_GAME_BOY_ADVANCE_EREADER,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Game Boy Color
add_platform(
    Platform.NINTENDO_GAME_BOY_COLOR,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Gamecube
add_platform(
    Platform.NINTENDO_GAMECUBE,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo NES
add_platform(
    Platform.NINTENDO_NES,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo SNES
add_platform(
    Platform.NINTENDO_SNES,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo SNES MSU-1
add_platform(
    Platform.NINTENDO_SNES_MSU1,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Super Famicom
add_platform(
    Platform.NINTENDO_SUPER_FAMICOM,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Super Game Boy
add_platform(
    Platform.NINTENDO_SUPER_GAME_BOY,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Super Game Boy Color
add_platform(
    Platform.NINTENDO_SUPER_GAME_BOY_COLOR,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Switch
add_platform(
    Platform.NINTENDO_SWITCH,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Switch eShop
add_platform(
    Platform.NINTENDO_SWITCH_ESHOP,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Virtual Boy
add_platform(
    Platform.NINTENDO_VIRTUAL_BOY,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Wii
add_platform(
    Platform.NINTENDO_WII,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Wii U
add_platform(
    Platform.NINTENDO_WII_U,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo Wii U eShop
add_platform(
    Platform.NINTENDO_WII_U_ESHOP,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nintendo WiiWare
add_platform(
    Platform.NINTENDO_WIIWARE,
    categories.Category.NINTENDO,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Apple iOS
add_platform(
    Platform.OTHER_APPLE_IOS,
    categories.Category.OTHER,
    types.LaunchType.NO_LAUNCHER)

# Apple MacOS 8
add_platform(
    Platform.OTHER_APPLE_MACOS_8,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Arcade
add_platform(
    Platform.OTHER_ARCADE,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_NAME,
    fillonce = [keys.json_key_launch_name])

# Atari 800
add_platform(
    Platform.OTHER_ATARI_800,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Atari 2600
add_platform(
    Platform.OTHER_ATARI_2600,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Atari 5200
add_platform(
    Platform.OTHER_ATARI_5200,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Atari 7800
add_platform(
    Platform.OTHER_ATARI_7800,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Atari Jaguar
add_platform(
    Platform.OTHER_ATARI_JAGUAR,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Atari Jaguar CD
add_platform(
    Platform.OTHER_ATARI_JAGUAR_CD,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Atari Lynx
add_platform(
    Platform.OTHER_ATARI_LYNX,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Bandai WonderSwan
add_platform(
    Platform.OTHER_BANDAI_WONDERSWAN,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Bandai WonderSwan Color
add_platform(
    Platform.OTHER_BANDAI_WONDERSWAN_COLOR,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Coleco ColecoVision
add_platform(
    Platform.OTHER_COLECO_COLECOVISION,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Commodore 64
add_platform(
    Platform.OTHER_COMMODORE_64,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Commodore Amiga
add_platform(
    Platform.OTHER_COMMODORE_AMIGA,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Google Android
add_platform(
    Platform.OTHER_GOOGLE_ANDROID,
    categories.Category.OTHER,
    types.LaunchType.NO_LAUNCHER)

# Magnavox Odyssey 2
add_platform(
    Platform.OTHER_MAGNAVOX_ODYSSEY_2,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Mattel Intellivision
add_platform(
    Platform.OTHER_MATTEL_INTELLIVISION,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# NEC PC-Engine
add_platform(
    Platform.OTHER_NEC_PCENGINE,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# NEC PC-Engine CD
add_platform(
    Platform.OTHER_NEC_PCENGINE_CD,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# NEC SuperGrafx
add_platform(
    Platform.OTHER_NEC_SUPERGRAFX,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# NEC TurboGrafx-16
add_platform(
    Platform.OTHER_NEC_TURBOGRAFX_16,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# NEC TurboGrafx CD
add_platform(
    Platform.OTHER_NEC_TURBOGRAFX_CD,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Nokia N-Gage
add_platform(
    Platform.OTHER_NOKIA_NGAGE,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_NAME,
    fillonce = [keys.json_key_launch_name])

# Panasonic 3DO
add_platform(
    Platform.OTHER_PANASONIC_3DO,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Philips CDi
add_platform(
    Platform.OTHER_PHILIPS_CDI,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# SNK Neo Geo Pocket Color
add_platform(
    Platform.OTHER_SNK_NEOGEO_POCKET_COLOR,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sega 32X
add_platform(
    Platform.OTHER_SEGA_32X,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sega CD
add_platform(
    Platform.OTHER_SEGA_CD,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sega CD 32X
add_platform(
    Platform.OTHER_SEGA_CD_32X,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sega Dreamcast
add_platform(
    Platform.OTHER_SEGA_DREAMCAST,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sega Game Gear
add_platform(
    Platform.OTHER_SEGA_GAME_GEAR,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sega Genesis
add_platform(
    Platform.OTHER_SEGA_GENESIS,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sega Master System
add_platform(
    Platform.OTHER_SEGA_MASTER_SYSTEM,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sega Saturn
add_platform(
    Platform.OTHER_SEGA_SATURN,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sinclair ZX Spectrum
add_platform(
    Platform.OTHER_SINCLAIR_ZX_SPECTRUM,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Texas Instruments TI-99-4A
add_platform(
    Platform.OTHER_TEXAS_INSTRUMENTS_TI994A,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Tiger Game.com
add_platform(
    Platform.OTHER_TIGER_GAMECOM,
    categories.Category.OTHER,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sony PlayStation
add_platform(
    Platform.SONY_PLAYSTATION,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sony PlayStation 2
add_platform(
    Platform.SONY_PLAYSTATION_2,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sony PlayStation 3
add_platform(
    Platform.SONY_PLAYSTATION_3,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_transform_file],
    fillonce = [keys.json_key_launch_file])

# Sony PlayStation 4
add_platform(
    Platform.SONY_PLAYSTATION_4,
    categories.Category.SONY,
    types.LaunchType.NO_LAUNCHER,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES])

# Sony PlayStation Network - PlayStation 3
add_platform(
    Platform.SONY_PLAYSTATION_NETWORK_PS3,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_transform_file],
    fillonce = [keys.json_key_launch_file])

# Sony PlayStation Network - PlayStation 4
add_platform(
    Platform.SONY_PLAYSTATION_NETWORK_PS4,
    categories.Category.SONY,
    types.LaunchType.NO_LAUNCHER,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES])

# Sony PlayStation Network - PlayStation Portable
add_platform(
    Platform.SONY_PLAYSTATION_NETWORK_PSP,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sony PlayStation Network - PlayStation Portable Minis
add_platform(
    Platform.SONY_PLAYSTATION_NETWORK_PSPM,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_FILE,
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sony PlayStation Network - PlayStation Vita
add_platform(
    Platform.SONY_PLAYSTATION_NETWORK_PSV,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_NAME,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_transform_file],
    fillonce = [keys.json_key_launch_name])

# Sony PlayStation Portable
add_platform(
    Platform.SONY_PLAYSTATION_PORTABLE,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_FILE,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    autofill = [keys.json_key_files, keys.json_key_launch_file])

# Sony PlayStation Portable Video
add_platform(
    Platform.SONY_PLAYSTATION_PORTABLE_VIDEO,
    categories.Category.SONY,
    types.LaunchType.NO_LAUNCHER)

# Sony PlayStation Vita
add_platform(
    Platform.SONY_PLAYSTATION_VITA,
    categories.Category.SONY,
    types.LaunchType.LAUNCH_NAME,
    addons = [types.AddonType.DLC, types.AddonType.UPDATES],
    fillonce = [keys.json_key_launch_name])
