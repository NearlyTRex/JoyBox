import os, os.path
from xml.dom import minidom

f = open("datfile.txt", "w", encoding='utf-8', errors='ignore')

for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        if name.endswith(".dat"):
            dom = minidom.parse(os.path.join(root, name))
            games = dom.getElementsByTagName('game')
            for game in games:
                file_desc = game.attributes['name'].value
                rom_tags = game.getElementsByTagName("rom")
                for rom in rom_tags:
                    file_name = rom.attributes['name'].value
                    file_md5 = rom.attributes['md5'].value
                    file_sha256 = "MISSING"
                    f.write("%s || %s || %s || %s\n" % (file_desc, file_name, file_md5, file_sha256))
f.close()
