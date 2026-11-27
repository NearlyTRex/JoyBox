# Imports
from xml.dom import minidom

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import serialization
from joybox import fileops
from joybox import hashutil

# General datfile class
class Dat:

    # Constructor
    def __init__(self):
        self.game_database = {}

    # Add game entry
    def add_game(self, game_entry):
        game_md5 = game_entry[config.DAT_KEY_MD5]
        self.game_database[game_md5] = game_entry

    # Check if md5 is present
    def is_md5_present(self, md5):
        return md5 in self.game_database

    # Get by md5
    def get_by_md5(self, md5):
        if md5 not in self.game_database:
            return None
        return self.game_database[md5]

    # Import cache dat file
    def import_cache_dat_file(self, dat_file, verbose = False, pretend_run = False, exit_on_failure = False):
        if verbose:
            logger.log_info("Importing cache dat file '%s'" % dat_file)
        if not pretend_run:
            lines = serialization.read_text_lines(dat_file, exit_on_failure = exit_on_failure)
            if lines is None:
                return False
            for line in lines:
                line_tokens = line.strip().split(" || ")
                if len(line_tokens) >= 5:
                    game_entry = {}
                    game_entry[config.DAT_KEY_GAME] = line_tokens[0]
                    game_entry[config.DAT_KEY_FILE] = line_tokens[1]
                    game_entry[config.DAT_KEY_SIZE] = line_tokens[2]
                    game_entry[config.DAT_KEY_CRC] = line_tokens[3]
                    game_entry[config.DAT_KEY_MD5] = line_tokens[4]
                    self.add_game(game_entry)
        return True

    # Export cache dat file
    def export_cache_dat_file(self, dat_file, verbose = False, pretend_run = False, exit_on_failure = False):
        if verbose:
            logger.log_info("Exporting cache dat file '%s'" % dat_file)
        if not pretend_run:
            fields = (config.DAT_KEY_GAME, config.DAT_KEY_FILE, config.DAT_KEY_SIZE, config.DAT_KEY_CRC, config.DAT_KEY_MD5)
            contents = "".join(
                " || ".join(game_entry[field] for field in fields) + "\n" for game_entry in self.game_database.values())
            return serialization.write_text_file(dat_file, contents, exit_on_failure = exit_on_failure)
        return True

    # Import clrmamepro dat file
    def import_clrmamepro_dat_file(self, dat_file, verbose = False, pretend_run = False, exit_on_failure = False):
        try:
            if verbose:
                logger.log_info("Importing clrmamepro dat file '%s'" % dat_file)
            if not pretend_run:
                dom = minidom.parse(dat_file)
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
                        game_entry[config.DAT_KEY_GAME] = game_tag.attributes["name"].value
                        game_entry[config.DAT_KEY_FILE] = paths.get_filename_file(rom_tag.attributes["name"].value.replace("\\", "/"))
                        game_entry[config.DAT_KEY_SIZE] = rom_tag.attributes["size"].value
                        game_entry[config.DAT_KEY_CRC] = rom_tag.attributes["crc"].value
                        game_entry[config.DAT_KEY_MD5] = rom_tag.attributes["md5"].value
                        self.add_game(game_entry)
            return True
        except Exception as e:
            if exit_on_failure:
                logger.log_error("Unable to import clrmamepro dat file '%s'" % dat_file)
                logger.log_error(e, quit_program = True)
            return False

    # Import clrmamepro dat files
    def import_clrmamepro_dat_files(self, dat_dir, verbose = False, pretend_run = False, exit_on_failure = False):
        for dat_file in paths.build_file_list_by_extensions(dat_dir, extensions = [".dat"]):
            self.import_clrmamepro_dat_file(dat_file, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Rename files
    def rename_files(self, input_dir, verbose = False, pretend_run = False, exit_on_failure = False):
        if verbose:
            logger.log_info("Renaming files in '%s' according to imported dats ..." % input_dir)
        for file in paths.build_file_list(input_dir):
            if verbose:
                logger.log_info("Examining '%s'" % file)
            file_dir = paths.get_filename_directory(file)
            file_md5 = hashutil.calculate_file_md5(file, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
            if self.is_md5_present(file_md5):
                game_entry = self.get_by_md5(file_md5)
                file_path_new = paths.join_paths(file_dir, game_entry[config.DAT_KEY_FILE])
                if file != file_path_new:
                    fileops.move_file_or_directory(
                        src = file,
                        dest = file_path_new,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
