# Imports
import os
import sys

# Local imports
from . import types

# Supercategory
class Supercategory(types.EnumType):
    ASSETS                              = ("Assets")
    EMULATORS                           = ("Emulators")
    ROMS                                = ("Roms")
    DLC                                 = ("DLC")
    UPDATES                             = ("Updates")
    TAGS                                = ("Tags")
    SAVES                               = ("Saves")
    SETUP                               = ("Setup")
    INSTALLS                            = ("Installs")

# Category
class Category(types.EnumType):
    COMPUTER                            = ("Computer")
    MICROSOFT                           = ("Microsoft")
    NINTENDO                            = ("Nintendo")
    OTHER                               = ("Other")
    SONY                                = ("Sony")

# Subcategory
class Subcategory(types.EnumType):

    # Computer
    COMPUTER_AMAZON_GAMES               = ("Amazon Games")
    COMPUTER_DISC                       = ("Disc")
    COMPUTER_EPIC_GAMES                 = ("Epic Games")
    COMPUTER_GOG                        = ("GOG")
    COMPUTER_HUMBLE_BUNDLE              = ("Humble Bundle")
    COMPUTER_ITCHIO                     = ("Itchio")
    COMPUTER_LEGACY_GAMES               = ("Legacy Games")
    COMPUTER_PUPPET_COMBO               = ("Puppet Combo")
    COMPUTER_RED_CANDLE                 = ("Red Candle")
    COMPUTER_SQUARE_ENIX                = ("Square Enix")
    COMPUTER_STEAM                      = ("Steam")
    COMPUTER_ZOOM                       = ("Zoom")

    # Microsoft
    MICROSOFT_MSX                       = ("Microsoft MSX")
    MICROSOFT_XBOX                      = ("Microsoft Xbox")
    MICROSOFT_XBOX_360                  = ("Microsoft Xbox 360")
    MICROSOFT_XBOX_360_GOD              = ("Microsoft Xbox 360 GOD")
    MICROSOFT_XBOX_360_XBLA             = ("Microsoft Xbox 360 XBLA")
    MICROSOFT_XBOX_360_XIG              = ("Microsoft Xbox 360 XIG")
    MICROSOFT_XBOX_ONE                  = ("Microsoft Xbox One")
    MICROSOFT_XBOX_ONE_GOD              = ("Microsoft Xbox One GOD")

    # Nintendo
    NINTENDO_3DS                        = ("Nintendo 3DS")
    NINTENDO_3DS_APPS                   = ("Nintendo 3DS Apps")
    NINTENDO_3DS_ESHOP                  = ("Nintendo 3DS eShop")
    NINTENDO_64                         = ("Nintendo 64")
    NINTENDO_AMIIBO                     = ("Nintendo Amiibo")
    NINTENDO_DS                         = ("Nintendo DS")
    NINTENDO_DSI                        = ("Nintendo DSi")
    NINTENDO_FAMICOM                    = ("Nintendo Famicom")
    NINTENDO_GAME_BOY                   = ("Nintendo Game Boy")
    NINTENDO_GAME_BOY_ADVANCE           = ("Nintendo Game Boy Advance")
    NINTENDO_GAME_BOY_ADVANCE_EREADER   = ("Nintendo Game Boy Advance e-Reader")
    NINTENDO_GAME_BOY_COLOR             = ("Nintendo Game Boy Color")
    NINTENDO_GAMECUBE                   = ("Nintendo Gamecube")
    NINTENDO_NES                        = ("Nintendo NES")
    NINTENDO_SNES                       = ("Nintendo SNES")
    NINTENDO_SNES_MSU1                  = ("Nintendo SNES MSU-1")
    NINTENDO_SUPER_FAMICOM              = ("Nintendo Super Famicom")
    NINTENDO_SUPER_GAME_BOY             = ("Nintendo Super Game Boy")
    NINTENDO_SUPER_GAME_BOY_COLOR       = ("Nintendo Super Game Boy Color")
    NINTENDO_SWITCH                     = ("Nintendo Switch")
    NINTENDO_SWITCH_ESHOP               = ("Nintendo Switch eShop")
    NINTENDO_VIRTUAL_BOY                = ("Nintendo Virtual Boy")
    NINTENDO_WII                        = ("Nintendo Wii")
    NINTENDO_WII_U                      = ("Nintendo Wii U")
    NINTENDO_WII_U_ESHOP                = ("Nintendo Wii U eShop")
    NINTENDO_WIIWARE                    = ("Nintendo WiiWare")

    # Other
    OTHER_APPLE_IOS                     = ("Apple iOS")
    OTHER_APPLE_MACOS_8                 = ("Apple MacOS 8")
    OTHER_ARCADE                        = ("Arcade")
    OTHER_ATARI_800                     = ("Atari 800")
    OTHER_ATARI_2600                    = ("Atari 2600")
    OTHER_ATARI_5200                    = ("Atari 5200")
    OTHER_ATARI_7800                    = ("Atari 7800")
    OTHER_ATARI_JAGUAR                  = ("Atari Jaguar")
    OTHER_ATARI_JAGUAR_CD               = ("Atari Jaguar CD")
    OTHER_ATARI_LYNX                    = ("Atari Lynx")
    OTHER_BANDAI_WONDERSWAN             = ("Bandai WonderSwan")
    OTHER_BANDAI_WONDERSWAN_COLOR       = ("Bandai WonderSwan Color")
    OTHER_COLECO_COLECOVISION           = ("Coleco ColecoVision")
    OTHER_COMMODORE_64                  = ("Commodore 64")
    OTHER_COMMODORE_AMIGA               = ("Commodore Amiga")
    OTHER_GOOGLE_ANDROID                = ("Google Android")
    OTHER_MAGNAVOX_ODYSSEY_2            = ("Magnavox Odyssey 2")
    OTHER_MATTEL_INTELLIVISION          = ("Mattel Intellivision")
    OTHER_NEC_PCENGINE                  = ("NEC PC-Engine")
    OTHER_NEC_PCENGINE_CD               = ("NEC PC-Engine CD")
    OTHER_NEC_SUPERGRAFX                = ("NEC SuperGrafx")
    OTHER_NEC_TURBOGRAFX_16             = ("NEC TurboGrafx-16")
    OTHER_NEC_TURBOGRAFX_CD             = ("NEC TurboGrafx CD")
    OTHER_NOKIA_NGAGE                   = ("Nokia N-Gage")
    OTHER_PANASONIC_3DO                 = ("Panasonic 3DO")
    OTHER_PHILIPS_CDI                   = ("Philips CDi")
    OTHER_SNK_NEOGEO_POCKET_COLOR       = ("SNK Neo Geo Pocket Color")
    OTHER_SEGA_32X                      = ("Sega 32X")
    OTHER_SEGA_CD                       = ("Sega CD")
    OTHER_SEGA_CD_32X                   = ("Sega CD 32X")
    OTHER_SEGA_DREAMCAST                = ("Sega Dreamcast")
    OTHER_SEGA_GAME_GEAR                = ("Sega Game Gear")
    OTHER_SEGA_GENESIS                  = ("Sega Genesis")
    OTHER_SEGA_MASTER_SYSTEM            = ("Sega Master System")
    OTHER_SEGA_SATURN                   = ("Sega Saturn")
    OTHER_SINCLAIR_ZX_SPECTRUM          = ("Sinclair ZX Spectrum")
    OTHER_TEXAS_INSTRUMENTS_TI994A      = ("Texas Instruments TI-99-4A")
    OTHER_TIGER_GAMECOM                 = ("Tiger Game.com")

    # Sony
    SONY_PLAYSTATION                    = ("Sony PlayStation")
    SONY_PLAYSTATION_2                  = ("Sony PlayStation 2")
    SONY_PLAYSTATION_3                  = ("Sony PlayStation 3")
    SONY_PLAYSTATION_4                  = ("Sony PlayStation 4")
    SONY_PLAYSTATION_NETWORK_PS3        = ("Sony PlayStation Network - PlayStation 3")
    SONY_PLAYSTATION_NETWORK_PS4        = ("Sony PlayStation Network - PlayStation 4")
    SONY_PLAYSTATION_NETWORK_PSP        = ("Sony PlayStation Network - PlayStation Portable")
    SONY_PLAYSTATION_NETWORK_PSPM       = ("Sony PlayStation Network - PlayStation Portable Minis")
    SONY_PLAYSTATION_NETWORK_PSV        = ("Sony PlayStation Network - PlayStation Vita")
    SONY_PLAYSTATION_PORTABLE           = ("Sony PlayStation Portable")
    SONY_PLAYSTATION_PORTABLE_VIDEO     = ("Sony PlayStation Portable Video")
    SONY_PLAYSTATION_VITA               = ("Sony PlayStation Vita")

# Subcategory map
subcategory_map = {
    Category.COMPUTER: [
        Subcategory.COMPUTER_AMAZON_GAMES,
        Subcategory.COMPUTER_DISC,
        Subcategory.COMPUTER_EPIC_GAMES,
        Subcategory.COMPUTER_GOG,
        Subcategory.COMPUTER_HUMBLE_BUNDLE,
        Subcategory.COMPUTER_ITCHIO,
        Subcategory.COMPUTER_LEGACY_GAMES,
        Subcategory.COMPUTER_PUPPET_COMBO,
        Subcategory.COMPUTER_RED_CANDLE,
        Subcategory.COMPUTER_SQUARE_ENIX,
        Subcategory.COMPUTER_STEAM,
        Subcategory.COMPUTER_ZOOM
    ],
    Category.MICROSOFT: [
        Subcategory.MICROSOFT_MSX,
        Subcategory.MICROSOFT_XBOX,
        Subcategory.MICROSOFT_XBOX_360,
        Subcategory.MICROSOFT_XBOX_360_GOD,
        Subcategory.MICROSOFT_XBOX_360_XBLA,
        Subcategory.MICROSOFT_XBOX_360_XIG,
        Subcategory.MICROSOFT_XBOX_ONE,
        Subcategory.MICROSOFT_XBOX_ONE_GOD
    ],
    Category.NINTENDO: [
        Subcategory.NINTENDO_3DS,
        Subcategory.NINTENDO_3DS_APPS,
        Subcategory.NINTENDO_3DS_ESHOP,
        Subcategory.NINTENDO_64,
        Subcategory.NINTENDO_AMIIBO,
        Subcategory.NINTENDO_DS,
        Subcategory.NINTENDO_DSI,
        Subcategory.NINTENDO_FAMICOM,
        Subcategory.NINTENDO_GAME_BOY,
        Subcategory.NINTENDO_GAME_BOY_ADVANCE,
        Subcategory.NINTENDO_GAME_BOY_ADVANCE_EREADER,
        Subcategory.NINTENDO_GAME_BOY_COLOR,
        Subcategory.NINTENDO_GAMECUBE,
        Subcategory.NINTENDO_NES,
        Subcategory.NINTENDO_SNES,
        Subcategory.NINTENDO_SNES_MSU1,
        Subcategory.NINTENDO_SUPER_FAMICOM,
        Subcategory.NINTENDO_SUPER_GAME_BOY,
        Subcategory.NINTENDO_SUPER_GAME_BOY_COLOR,
        Subcategory.NINTENDO_SWITCH,
        Subcategory.NINTENDO_SWITCH_ESHOP,
        Subcategory.NINTENDO_VIRTUAL_BOY,
        Subcategory.NINTENDO_WII,
        Subcategory.NINTENDO_WII_U,
        Subcategory.NINTENDO_WII_U_ESHOP,
        Subcategory.NINTENDO_WIIWARE
    ],
    Category.OTHER: [
        Subcategory.OTHER_APPLE_IOS,
        Subcategory.OTHER_APPLE_MACOS_8,
        Subcategory.OTHER_ARCADE,
        Subcategory.OTHER_ATARI_800,
        Subcategory.OTHER_ATARI_2600,
        Subcategory.OTHER_ATARI_5200,
        Subcategory.OTHER_ATARI_7800,
        Subcategory.OTHER_ATARI_JAGUAR,
        Subcategory.OTHER_ATARI_JAGUAR_CD,
        Subcategory.OTHER_ATARI_LYNX,
        Subcategory.OTHER_BANDAI_WONDERSWAN,
        Subcategory.OTHER_BANDAI_WONDERSWAN_COLOR,
        Subcategory.OTHER_COLECO_COLECOVISION,
        Subcategory.OTHER_COMMODORE_64,
        Subcategory.OTHER_COMMODORE_AMIGA,
        Subcategory.OTHER_GOOGLE_ANDROID,
        Subcategory.OTHER_MAGNAVOX_ODYSSEY_2,
        Subcategory.OTHER_MATTEL_INTELLIVISION,
        Subcategory.OTHER_NEC_PCENGINE,
        Subcategory.OTHER_NEC_PCENGINE_CD,
        Subcategory.OTHER_NEC_SUPERGRAFX,
        Subcategory.OTHER_NEC_TURBOGRAFX_16,
        Subcategory.OTHER_NEC_TURBOGRAFX_CD,
        Subcategory.OTHER_NOKIA_NGAGE,
        Subcategory.OTHER_PANASONIC_3DO,
        Subcategory.OTHER_PHILIPS_CDI,
        Subcategory.OTHER_SNK_NEOGEO_POCKET_COLOR,
        Subcategory.OTHER_SEGA_32X,
        Subcategory.OTHER_SEGA_CD,
        Subcategory.OTHER_SEGA_CD_32X,
        Subcategory.OTHER_SEGA_DREAMCAST,
        Subcategory.OTHER_SEGA_GAME_GEAR,
        Subcategory.OTHER_SEGA_GENESIS,
        Subcategory.OTHER_SEGA_MASTER_SYSTEM,
        Subcategory.OTHER_SEGA_SATURN,
        Subcategory.OTHER_SINCLAIR_ZX_SPECTRUM,
        Subcategory.OTHER_TEXAS_INSTRUMENTS_TI994A,
        Subcategory.OTHER_TIGER_GAMECOM
    ],
    Category.SONY: [
        Subcategory.SONY_PLAYSTATION,
        Subcategory.SONY_PLAYSTATION_2,
        Subcategory.SONY_PLAYSTATION_3,
        Subcategory.SONY_PLAYSTATION_4,
        Subcategory.SONY_PLAYSTATION_NETWORK_PS3,
        Subcategory.SONY_PLAYSTATION_NETWORK_PS4,
        Subcategory.SONY_PLAYSTATION_NETWORK_PSP,
        Subcategory.SONY_PLAYSTATION_NETWORK_PSPM,
        Subcategory.SONY_PLAYSTATION_NETWORK_PSV,
        Subcategory.SONY_PLAYSTATION_PORTABLE,
        Subcategory.SONY_PLAYSTATION_PORTABLE_VIDEO,
        Subcategory.SONY_PLAYSTATION_VITA
    ]
}
