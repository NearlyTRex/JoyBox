# Imports
from xml.dom import minidom
from xml.parsers.expat import ExpatError

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import serialization
from joybox import fileops
from joybox import hashutil

# A game entry for one ROM of a dat game, or None when the game has no name or the ROM
# lacks a name, size, crc or md5
def _get_rom_entry(game_tag, rom_tag):
    has_name = game_tag.hasAttribute("name")
    has_file = rom_tag.hasAttribute("name")
    has_size = rom_tag.hasAttribute("size")
    has_crc = rom_tag.hasAttribute("crc")
    has_md5 = rom_tag.hasAttribute("md5")
    if not has_name or not has_file or not has_size or not has_crc or not has_md5:
        return None
    game_entry = {}
    game_entry[config.DAT_KEY_GAME] = game_tag.attributes["name"].value
    game_entry[config.DAT_KEY_FILE] = paths.get_filename_file(rom_tag.attributes["name"].value.replace("\\", "/"))
    game_entry[config.DAT_KEY_SIZE] = rom_tag.attributes["size"].value
    game_entry[config.DAT_KEY_CRC] = rom_tag.attributes["crc"].value
    game_entry[config.DAT_KEY_MD5] = rom_tag.attributes["md5"].value
    return game_entry

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

    # The game entry whose ROM has this MD5; None when no imported dat lists it
    def get_by_md5(self, md5):
        if md5 not in self.game_database:
            return None
        return self.game_database[md5]

    # Load entries from a " || "-separated cache file of game, file, size, crc and md5;
    # False when the file can't be read
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

    # Write every entry as a " || "-separated cache line of game, file, size, crc and md5
    def export_cache_dat_file(self, dat_file, verbose = False, pretend_run = False, exit_on_failure = False):
        if verbose:
            logger.log_info("Exporting cache dat file '%s'" % dat_file)
        if not pretend_run:
            fields = (config.DAT_KEY_GAME, config.DAT_KEY_FILE, config.DAT_KEY_SIZE, config.DAT_KEY_CRC, config.DAT_KEY_MD5)
            contents = "".join(
                " || ".join(game_entry[field] for field in fields) + "\n" for game_entry in self.game_database.values())
            return serialization.write_text_file(dat_file, contents, exit_on_failure = exit_on_failure)
        return True

    # Add an entry for each complete ROM of each game in a parsed clrmamepro dat
    def _add_dat_games(self, dom):
        game_tags = dom.getElementsByTagName("game")
        for game_tag in game_tags:
            rom_tags = game_tag.getElementsByTagName("rom")
            for rom_tag in rom_tags:
                game_entry = _get_rom_entry(game_tag, rom_tag)
                if game_entry:
                    self.add_game(game_entry)

    # Load each ROM of a clrmamepro XML dat, skipping ROMs missing a name, size, crc or md5;
    # False when the file can't be parsed
    def import_clrmamepro_dat_file(self, dat_file, verbose = False, pretend_run = False, exit_on_failure = False):
        try:
            if verbose:
                logger.log_info("Importing clrmamepro dat file '%s'" % dat_file)
            if not pretend_run:
                dom = minidom.parse(dat_file)
                self._add_dat_games(dom)
            return True
        except (OSError, KeyError, ExpatError) as e:
            if exit_on_failure:
                logger.log_error("Unable to import clrmamepro dat file '%s'" % dat_file)
                logger.log_error(e, quit_program = True)
            return False

    # Load every .dat under the directory as a clrmamepro dat
    def import_clrmamepro_dat_files(self, dat_dir, verbose = False, pretend_run = False, exit_on_failure = False):
        for dat_file in paths.build_file_list_by_extensions(dat_dir, extensions = [".dat"]):
            self.import_clrmamepro_dat_file(dat_file, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Rename each file under the directory to the file name its MD5 maps to in the imported dats
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

# Load records from the dat directory (writing them to the cache file when asked), or else from the
# cache file, then rename the files under the input directory by those records
def rename_files_using_dat(input_dir, dat_directory, dat_cachefile, generate_cachefile = False, verbose = False, pretend_run = False, exit_on_failure = False):
    game_dat = Dat()
    if paths.is_path_directory(dat_directory):
        game_dat.import_clrmamepro_dat_files(
            dat_dir = dat_directory,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if generate_cachefile:
            game_dat.export_cache_dat_file(
                dat_file = dat_cachefile,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    elif paths.is_path_file(dat_cachefile):
        game_dat.import_cache_dat_file(
            dat_file = dat_cachefile,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    game_dat.rename_files(
        input_dir = input_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
