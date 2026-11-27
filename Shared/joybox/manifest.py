# Imports
import functools

# Local imports
from joybox import containers
from joybox import programs
from joybox import serialization
from joybox import storepaths
from joybox import strings

# True when a "when" condition names Windows/DOS under Steam or no store, or Steam with no OS
def is_windows_save_condition(when_info):
    when_os = when_info["os"] if "os" in when_info else ""
    when_store = when_info["store"] if "store" in when_info else ""
    if when_os in ("windows", "dos") and when_store in ("steam", ""):
        return True
    return when_os == "" and when_store == "steam"

# Manifest entry
class ManifestEntry:

    # Constructor
    def __init__(self, manifest_data):
        self.manifest_data = manifest_data

    # Tokenized save paths under base_path for the Windows, DOS and Steam file entries
    def get_paths(self, base_path):
        paths = []
        if "files" not in self.manifest_data:
            return paths
        for path_location, path_info in self.manifest_data["files"].items():
            if "when" not in path_info:
                continue
            for when_info in path_info["when"]:
                if is_windows_save_condition(when_info):
                    paths.append(storepaths.create_tokenized_path(path_location, base_path))
        return paths

    # Registry keys the entry lists; empty when it has none
    def get_keys(self):
        keys = []
        if "registry" in self.manifest_data:
            for key in self.manifest_data["registry"]:
                keys.append(key)
        return keys

    # First installDir name the entry lists; None when it has none
    def get_install_dir(self):
        if "installDir" in self.manifest_data:
            for key in self.manifest_data["installDir"]:
                return key
        return None

# Ludusavi game manifest, keyed by game name
class Manifest:

    # Constructor
    def __init__(self, manifest = None):
        self.manifest = {}
        if manifest:
            self.manifest = manifest

    # Read the Ludusavi manifest YAML from the tool path the config names
    def load(self, verbose = False, exit_on_failure = False):
        self.manifest = serialization.read_yaml_file(
            src = programs.get_tool_path_config_value("LudusaviManifest", "yaml"),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Closest highly similar game name in the manifest; None when nothing matches
    def find_entry_by_name(self, name):
        search_results = []
        for manifest_name, manifest_entry in self.manifest.items():
            if strings.are_strings_highly_similar(manifest_name, name):
                search_result = containers.SearchResult()
                search_result.set_title(manifest_name)
                search_result.set_relevance(strings.get_string_similarity_ratio(name, manifest_name))
                search_result.set_result_data(manifest_entry)
                search_results.append(search_result)
        for search_result in sorted(search_results, key=lambda x: x.get_relevance(), reverse = True):
            return ManifestEntry(search_result.get_result_data())
        return None

    # Find entry by steam id
    def find_entry_by_steamid(self, steamid):
        for manifest_entry in self.manifest.values():
            if "steam" not in manifest_entry:
                continue
            if "id" not in manifest_entry["steam"]:
                continue
            if int(manifest_entry["steam"]["id"]) == int(steamid):
                return ManifestEntry(manifest_entry)
        return None

    # Find entry by gog id
    def find_entry_by_gogid(self, gogid):
        for manifest_entry in self.manifest.values():
            if "gog" not in manifest_entry:
                continue
            if "id" not in manifest_entry["gog"]:
                continue
            if int(manifest_entry["gog"]["id"]) == int(gogid):
                return ManifestEntry(manifest_entry)
        return None

# Get the manifest instance the process shares, built on first use
@functools.cache
def get_manifest_instance():
    return Manifest()
