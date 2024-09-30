# Imports
import os
import sys
import collections

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
gametype_weights[".txt"] = gametype_counter; gametype_counter += 1          # General index
gametype_weights[".zip"] = gametype_counter; gametype_counter += 1          # Zip archive

# Other game types
gametype_weight_else = 100
