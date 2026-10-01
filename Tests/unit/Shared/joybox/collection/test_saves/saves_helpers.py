# Imports
import os
import types

# Local imports
from joybox import config
from joybox.collection import saves


###########################################################
# Doubles
#
# Archiving, locker backup and duplicate detection are replaced by recorders;
# the save directories themselves are real directories under tmp_path.
###########################################################

class FakeGameInfo:

    def __init__(self, save_dir, local_save_dir, name = "Chrono Trigger (USA)",
                 category = None, platform = "Nintendo SNES", store_paths = None):
        self.save_dir = save_dir
        self.local_save_dir = local_save_dir
        self.name = name
        self.category = category or config.Category.NINTENDO
        self.platform = platform
        self.store_paths = store_paths
        self.updates = []
        self.update_result = True

    def get_name(self):
        return self.name

    def get_save_dir(self):
        return self.save_dir

    def get_local_save_dir(self):
        return self.local_save_dir

    def get_supercategory(self):
        return config.Supercategory.ROMS

    def get_category(self):
        return self.category

    def get_subcategory(self):
        return config.Subcategory.NINTENDO_SNES

    def get_platform(self):
        return self.platform

    def get_store_paths(self):
        return self.store_paths

    def set_store_paths(self, value):
        self.store_paths = value

    def get_store_appid(self):
        return "1145360"

    def get_store_name(self):
        return "Hades"

    def get_main_store_type(self):
        return "Steam"

    def update_json_file(self, **kwargs):
        self.updates.append(kwargs)
        return self.update_result


class FakeArchive:

    def __init__(self):
        self.created = []
        self.tested = []
        self.extracted = []
        self.listed = []
        self.create_result = True
        self.test_result = True
        self.extract_result = True
        self.extract_contents = {"slot1.sav": b"restored"}
        self.listings = {}

    def create_archive_from_folder(self, archive_file, source_dir, excludes, **kwargs):
        self.created.append({
            "archive_file": archive_file, "source_dir": source_dir,
            "excludes": excludes, **kwargs})
        if self.create_result and not kwargs.get("pretend_run"):
            with open(archive_file, "wb") as handle:
                handle.write(b"zip")
        return self.create_result

    def test_archive(self, archive_file, **kwargs):
        self.tested.append(archive_file)
        return self.test_result

    def extract_archive(self, archive_file, extract_dir, **kwargs):
        self.extracted.append({"archive_file": archive_file, "extract_dir": extract_dir, **kwargs})
        if self.extract_result and not kwargs.get("pretend_run"):
            for name, data in self.extract_contents.items():
                with open(os.path.join(extract_dir, name), "wb") as handle:
                    handle.write(data)
        return self.extract_result

    def list_archive(self, archive_file, **kwargs):
        self.listed.append(archive_file)
        return self.listings.get(os.path.basename(archive_file), [])


class FakeLocker:

    def __init__(self):
        self.backups = []
        self.result = True

    def convert_to_relative_path(self, path):
        return os.path.join("Gaming", "Saves", os.path.basename(path))

    def backup(self, src, dest_rel_path, locker_type = None, **kwargs):
        self.backups.append({
            "src": src, "dest_rel_path": dest_rel_path,
            "locker_type": locker_type, "existed": os.path.exists(src), **kwargs})
        return self.result


class FakeHashing:

    def __init__(self):
        self.duplicates = []
        self.asked = []

    def find_duplicate_archives(self, filename, directory, **kwargs):
        self.asked.append((filename, directory))
        return self.duplicates


def make_catalog(monkeypatch, games):
    # games maps a game name to its FakeGameInfo, all under Nintendo SNES
    built = []

    def find_json_game_names(supercategory, category, subcategory):
        if category == config.Category.NINTENDO and subcategory == config.Subcategory.NINTENDO_SNES:
            return list(games)
        return []

    def game_info_factory(game_name, **kwargs):
        built.append((game_name, kwargs))
        return games[game_name]

    monkeypatch.setattr(saves, "gameinfo", types.SimpleNamespace(
        find_json_game_names = find_json_game_names,
        GameInfo = game_info_factory))
    return built
