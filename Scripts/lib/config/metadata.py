# Imports
import os
import sys
import collections

# Local imports
from . import platforms

######################################################################################

# Game type weights
gametype_counter = 0
gametype_weights = collections.OrderedDict()
gametype_weights[".m3u"] = gametype_counter; gametype_counter += 1          # Playlist
gametype_weights[".json"] = gametype_counter; gametype_counter += 1         # Json
gametype_weights[".exe"] = gametype_counter; gametype_counter += 1          # Windows executable
gametype_weights[".msi"] = gametype_counter; gametype_counter += 1          # Windows installer
gametype_weights[".apk"] = gametype_counter; gametype_counter += 1          # Google Android
gametype_weights[".ipa"] = gametype_counter; gametype_counter += 1          # Apple iOS
gametype_weights[".img"] = gametype_counter; gametype_counter += 1          # Apple MacOS 8
gametype_weights[".adf"] = gametype_counter; gametype_counter += 1          # Commodore Amiga - Disk
gametype_weights[".g64"] = gametype_counter; gametype_counter += 1          # Commodore 64 - G64
gametype_weights[".crt"] = gametype_counter; gametype_counter += 1          # Commodore 64 - Cartridge
gametype_weights[".tap"] = gametype_counter; gametype_counter += 1          # Commodore 64 - Tape
gametype_weights[".ipf"] = gametype_counter; gametype_counter += 1          # Commodore 64 - Disk
gametype_weights[".lnx"] = gametype_counter; gametype_counter += 1          # Atari Lynx
gametype_weights[".nes"] = gametype_counter; gametype_counter += 1          # Nintendo NES
gametype_weights[".sfc"] = gametype_counter; gametype_counter += 1          # Nintendo SNES
gametype_weights[".gba"] = gametype_counter; gametype_counter += 1          # Nintendo GBA
gametype_weights[".nds"] = gametype_counter; gametype_counter += 1          # Nintendo DS/i
gametype_weights[".trim.3ds"] = gametype_counter; gametype_counter += 1     # Nintendo 3DS
gametype_weights[".trim.xci"] = gametype_counter; gametype_counter += 1     # Nintendo Switch Cartridge
gametype_weights[".nsp"] = gametype_counter; gametype_counter += 1          # Nintendo Swith eShop
gametype_weights[".rvz"] = gametype_counter; gametype_counter += 1          # Nintendo Wii/Gamecube
gametype_weights[".iso.wux"] = gametype_counter; gametype_counter += 1      # Nintendo Wii U Disc
gametype_weights[".wua"] = gametype_counter; gametype_counter += 1          # Nintendo Wii U eShop
gametype_weights[".cue"] = gametype_counter; gametype_counter += 1          # General disc - CUE
gametype_weights[".chd"] = gametype_counter; gametype_counter += 1          # General disc - CHD
gametype_weights[".ccd"] = gametype_counter; gametype_counter += 1          # General disc - CCD
gametype_weights[".cdi"] = gametype_counter; gametype_counter += 1          # General disc - CDI
gametype_weights[".pkg"] = gametype_counter; gametype_counter += 1          # Sony PSN Package
gametype_weights[".zip"] = gametype_counter; gametype_counter += 1          # Zip archive
gametype_weights[".txt"] = gametype_counter; gametype_counter += 1          # Text file

# Other game types
gametype_weight_else = 100

######################################################################################

# GameFAQs platforms
gamefaqs_platforms = {}

# Computer
gamefaqs_platforms[platforms.Platform.COMPUTER_AMAZON_GAMES]                = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_DISC]                        = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_EPIC_GAMES]                  = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_GOG]                         = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_HUMBLE_BUNDLE]               = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_ITCHIO]                      = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_LEGACY_GAMES]                = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_PUPPET_COMBO]                = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_RED_CANDLE]                  = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_SQUARE_ENIX]                 = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_STEAM]                       = ("PC", "19")
gamefaqs_platforms[platforms.Platform.COMPUTER_ZOOM]                        = ("PC", "19")

# Microsoft
gamefaqs_platforms[platforms.Platform.MICROSOFT_MSX]                        = ("MSX", "40")
gamefaqs_platforms[platforms.Platform.MICROSOFT_XBOX]                       = ("XBOX", "98")
gamefaqs_platforms[platforms.Platform.MICROSOFT_XBOX_360]                   = ("X360", "111")
gamefaqs_platforms[platforms.Platform.MICROSOFT_XBOX_360_GOD]               = ("X360", "111")
gamefaqs_platforms[platforms.Platform.MICROSOFT_XBOX_360_XBLA]              = ("X360", "111")
gamefaqs_platforms[platforms.Platform.MICROSOFT_XBOX_360_XIG]               = ("X360", "111")
gamefaqs_platforms[platforms.Platform.MICROSOFT_XBOX_ONE]                   = ("XONE", "121")
gamefaqs_platforms[platforms.Platform.MICROSOFT_XBOX_ONE_GOD]               = ("XONE", "121")

# Nintendo
gamefaqs_platforms[platforms.Platform.NINTENDO_3DS]                         = ("3DS", "116")
gamefaqs_platforms[platforms.Platform.NINTENDO_3DS_APPS]                    = ("3DS", "116")
gamefaqs_platforms[platforms.Platform.NINTENDO_3DS_ESHOP]                   = ("3DS", "116")
gamefaqs_platforms[platforms.Platform.NINTENDO_64]                          = ("N64", "84")
gamefaqs_platforms[platforms.Platform.NINTENDO_AMIIBO]                      = ("AMIIBO", "143")
gamefaqs_platforms[platforms.Platform.NINTENDO_DS]                          = ("DS", "108")
gamefaqs_platforms[platforms.Platform.NINTENDO_DSI]                         = ("DS", "108")
gamefaqs_platforms[platforms.Platform.NINTENDO_FAMICOM]                     = ("NES", "41")
gamefaqs_platforms[platforms.Platform.NINTENDO_GAME_BOY]                    = ("GB", "59")
gamefaqs_platforms[platforms.Platform.NINTENDO_GAME_BOY_ADVANCE]            = ("GBA", "91")
gamefaqs_platforms[platforms.Platform.NINTENDO_GAME_BOY_ADVANCE_EREADER]    = ("ERDR", "101")
gamefaqs_platforms[platforms.Platform.NINTENDO_GAME_BOY_COLOR]              = ("GBC", "57")
gamefaqs_platforms[platforms.Platform.NINTENDO_GAMECUBE]                    = ("GC", "99")
gamefaqs_platforms[platforms.Platform.NINTENDO_NES]                         = ("NES", "41")
gamefaqs_platforms[platforms.Platform.NINTENDO_SNES]                        = ("SNES", "63")
gamefaqs_platforms[platforms.Platform.NINTENDO_SNES_MSU1]                   = ("SNES", "63")
gamefaqs_platforms[platforms.Platform.NINTENDO_SUPER_FAMICOM]               = ("SNES", "63")
gamefaqs_platforms[platforms.Platform.NINTENDO_SUPER_GAME_BOY]              = ("GB", "59")
gamefaqs_platforms[platforms.Platform.NINTENDO_SUPER_GAME_BOY_COLOR]        = ("GBC", "57")
gamefaqs_platforms[platforms.Platform.NINTENDO_SWITCH]                      = ("NS", "124")
gamefaqs_platforms[platforms.Platform.NINTENDO_SWITCH_ESHOP]                = ("NS", "124")
gamefaqs_platforms[platforms.Platform.NINTENDO_VIRTUAL_BOY]                 = ("VBOY", "83")
gamefaqs_platforms[platforms.Platform.NINTENDO_WII]                         = ("WII", "114")
gamefaqs_platforms[platforms.Platform.NINTENDO_WII_U]                       = ("WIIU", "118")
gamefaqs_platforms[platforms.Platform.NINTENDO_WII_U_ESHOP]                 = ("WIIU", "118")
gamefaqs_platforms[platforms.Platform.NINTENDO_WIIWARE]                     = ("WII", "114")

# Other
gamefaqs_platforms[platforms.Platform.OTHER_APPLE_IOS]                      = ("IOS", "112")
gamefaqs_platforms[platforms.Platform.OTHER_APPLE_MACOS_8]                  = ("MAC", "27")
gamefaqs_platforms[platforms.Platform.OTHER_ARCADE]                         = ("ARC", "2")
gamefaqs_platforms[platforms.Platform.OTHER_ATARI_800]                      = ("A800", "13")
gamefaqs_platforms[platforms.Platform.OTHER_ATARI_2600]                     = ("2600", "6")
gamefaqs_platforms[platforms.Platform.OTHER_ATARI_5200]                     = ("5200", "20")
gamefaqs_platforms[platforms.Platform.OTHER_ATARI_7800]                     = ("7800", "51")
gamefaqs_platforms[platforms.Platform.OTHER_ATARI_JAGUAR]                   = ("JAG", "72")
gamefaqs_platforms[platforms.Platform.OTHER_ATARI_JAGUAR_CD]                = ("JCD", "82")
gamefaqs_platforms[platforms.Platform.OTHER_ATARI_LYNX]                     = ("LYNX", "58")
gamefaqs_platforms[platforms.Platform.OTHER_BANDAI_WONDERSWAN]              = ("WS", "90")
gamefaqs_platforms[platforms.Platform.OTHER_BANDAI_WONDERSWAN_COLOR]        = ("WSC", "95")
gamefaqs_platforms[platforms.Platform.OTHER_COLECO_COLECOVISION]            = ("CVIS", "29")
gamefaqs_platforms[platforms.Platform.OTHER_COMMODORE_64]                   = ("C64", "24")
gamefaqs_platforms[platforms.Platform.OTHER_COMMODORE_AMIGA]                = ("AMI", "39")
gamefaqs_platforms[platforms.Platform.OTHER_GOOGLE_ANDROID]                 = ("AND", "106")
gamefaqs_platforms[platforms.Platform.OTHER_MAGNAVOX_ODYSSEY_2]             = ("O2", "9")
gamefaqs_platforms[platforms.Platform.OTHER_MATTEL_INTELLIVISION]           = ("INTV", "16")
gamefaqs_platforms[platforms.Platform.OTHER_NEC_PCENGINE]                   = ("TG16", "53")
gamefaqs_platforms[platforms.Platform.OTHER_NEC_PCENGINE_CD]                = ("TCD", "56")
gamefaqs_platforms[platforms.Platform.OTHER_NEC_SUPERGRAFX]                 = ("TG16", "53")
gamefaqs_platforms[platforms.Platform.OTHER_NEC_TURBOGRAFX_16]              = ("TG16", "53")
gamefaqs_platforms[platforms.Platform.OTHER_NEC_TURBOGRAFX_CD]              = ("TCD", "56")
gamefaqs_platforms[platforms.Platform.OTHER_NOKIA_NGAGE]                    = ("NGE", "105")
gamefaqs_platforms[platforms.Platform.OTHER_PANASONIC_3DO]                  = ("3DO", "61")
gamefaqs_platforms[platforms.Platform.OTHER_PHILIPS_CDI]                    = ("CDI", "60")
gamefaqs_platforms[platforms.Platform.OTHER_SNK_NEOGEO_POCKET_COLOR]        = ("NGPC", "89")
gamefaqs_platforms[platforms.Platform.OTHER_SEGA_32X]                       = ("32X", "74")
gamefaqs_platforms[platforms.Platform.OTHER_SEGA_CD]                        = ("SCD", "65")
gamefaqs_platforms[platforms.Platform.OTHER_SEGA_CD_32X]                    = ("SCD", "65")
gamefaqs_platforms[platforms.Platform.OTHER_SEGA_DREAMCAST]                 = ("DC", "67")
gamefaqs_platforms[platforms.Platform.OTHER_SEGA_GAME_GEAR]                 = ("GG", "62")
gamefaqs_platforms[platforms.Platform.OTHER_SEGA_GENESIS]                   = ("GEN", "54")
gamefaqs_platforms[platforms.Platform.OTHER_SEGA_MASTER_SYSTEM]             = ("SMS", "49")
gamefaqs_platforms[platforms.Platform.OTHER_SEGA_SATURN]                    = ("SAT", "76")
gamefaqs_platforms[platforms.Platform.OTHER_SINCLAIR_ZX_SPECTRUM]           = ("ZX", "35")
gamefaqs_platforms[platforms.Platform.OTHER_TEXAS_INSTRUMENTS_TI994A]       = ("TI", "14")
gamefaqs_platforms[platforms.Platform.OTHER_TIGER_GAMECOM]                  = ("GCOM", "86")

# Sony
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION]                     = ("PS", "78")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_2]                   = ("PS2", "94")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_3]                   = ("PS3", "113")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_4]                   = ("PS4", "120")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_NETWORK_PS3]         = ("PS3", "113")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_NETWORK_PS4]         = ("PS4", "120")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_NETWORK_PSP]         = ("PSP", "109")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_NETWORK_PSPM]        = ("PSP", "109")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_NETWORK_PSV]         = ("VITA", "117")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_PORTABLE]            = ("PSP", "109")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_PORTABLE_VIDEO]      = ("PSP", "109")
gamefaqs_platforms[platforms.Platform.SONY_PLAYSTATION_VITA]                = ("VITA", "117")

######################################################################################
