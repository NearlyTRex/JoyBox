# Imports
import os, os.path
import sys
from xml.dom import minidom

# Local imports
import config
import system
import environment
import hashing

# General datfile class
class Dat:

    # Constructor
    def __init__(self):
        self.game_database = {}

    # Add game entry
    def add_game(self, game_entry):
        game_md5 = game_entry[config.dat_key_md5]
        self.game_database[game_md5] = game_entry

    # Check if md5 is present
    def is_md5_present(self, md5):
        return md5 in self.game_database

    # Get by md5
    def get_by_md5(self, md5):
        if md5 not in self.game_database:
            return None
        return self.game_database[md5]

    # Import clrmamepro dat file
    def import_clrmamepro_dat_file(self, input_file, verbose = False, exit_on_failure = False):
        try:
            if verbose:
                system.Log("Importing clrmamepro dat file '%s'" % input_file)
            dom = minidom.parse(input_file)
            game_tags = dom.getElementsByTagName("game")
            for game_tag in game_tags:
                rom_tags = game_tag.getElementsByTagName("rom")
                for rom_tag in rom_tags:
                    has_name = game_tag.hasAttribute("name")
                    has_file = rom_tag.hasAttribute("name")
                    has_size = rom_tag.hasAttribute("size")
                    has_crc = rom_tag.hasAttribute("crc")
                    has_md5 = rom_tag.hasAttribute("md5")
                    if not has_name or not has_file or not has_size or not has_crc or not has_md5:
                        continue
                    game_entry = {}
                    game_entry[config.dat_key_game] = game_tag.attributes["name"].value
                    game_entry[config.dat_key_file] = rom_tag.attributes["name"].value
                    game_entry[config.dat_key_size] = rom_tag.attributes["size"].value
                    game_entry[config.dat_key_crc] = rom_tag.attributes["crc"].value
                    game_entry[config.dat_key_md5] = rom_tag.attributes["md5"].value
                    self.add_game(game_entry)
        except Exception as e:
            if exit_on_failure:
                system.LogError("Unable to import clrmamepro dat file '%s'" % input_file)
                system.LogError(e)
                sys.exit(1)
            return False

    # Import clrmamepro dat files
    def import_clrmamepro_dat_files(self, input_path, verbose = False, exit_on_failure = False):
        for input_file in system.BuildFileListByExtensions(input_path, extensions = [".dat"]):
            self.import_clrmamepro_dat_file(input_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Rename files
    def rename_files(self, input_path, verbose = False, exit_on_failure = False):
        if verbose:
            system.LogInfo("Renaming files in '%s' according to imported dats ..." % input_path)
        for file in system.BuildFileList(input_path):
            if verbose:
                system.Log("Examining '%s'" % file)
            file_dir = system.GetFilenameDirectory(file)
            file_md5 = hashimg.CalculateFileMD5(filename, verbose = verbose, exit_on_failure = exit_on_failure)
            if self.is_md5_present(md5):
                game_entry = self.get_by_md5(md5)
                file_path_new = os.path.join(file_dir, game_entry[config.dat_key_file])
                if file != file_path_new:
                    system.MoveFileOrDirectory(
                        src = file,
                        dest = file_path_new,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
