# Imports
import os
import os.path
import sys

# Local imports
import config
import system
import environment
import containers
import programs
import storebase

# Manifest entry
class ManifestEntry:

    # Constructor
    def __init__(self, manifest_data):
        self.manifest_data = manifest_data

    # Get paths
    def get_paths(self, base_path):
        paths = []
        if "files" in self.manifest_data:
            for path_location, path_info in self.manifest_data["files"].items():
                if "when" in path_info:
                    for when_info in path_info["when"]:
                        when_os = when_info["os"] if "os" in when_info else ""
                        when_store = when_info["store"] if "store" in when_info else ""
                        is_windows_path = False
                        if (when_os == "windows" or when_os == "dos") and (when_store == "steam" or when_store == ""):
                            is_windows_path = True
                        elif when_os == "" and when_store == "steam":
                            is_windows_path = True
                        if is_windows_path:
                            paths.append(storebase.TranslateStorePath(path_location, base_path))
        return paths

    # Get keys
    def get_keys(self):
        keys = []
        if "registry" in self.manifest_data:
            for key in self.manifest_data["registry"]:
                keys.append(key)
        return keys

    # Get install dir
    def get_install_dir(self):
        if "installDir" in self.manifest_data:
            for key, value in self.manifest_data["installDir"]:
                return key
        return None

# Manifest class
class Manifest:

    # Constructor
    def __init__(self):
        self.manifest = {}

    # Load
    def load(self, verbose = False, pretend_run = False, exit_on_failure = False):
        self.manifest = system.ReadYamlFile(
            src = programs.GetToolPathConfigValue("LudusaviManifest", "yaml"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Find entry by name
    def find_entry_by_name(self, name, verbose = False, pretend_run = False, exit_on_failure = False):
        search_results = []
        for manifest_name, manifest_entry in self.manifest.items():
            if system.AreStringsHighlySimilar(manifest_name, name):
                search_result = containers.SearchResult()
                search_result.set_title(manifest_name)
                search_result.set_relevance(system.GetStringSimilarityRatio(name, manifest_name))
                search_result.set_data(manifest_entry)
                search_results.append(search_result)
        for search_result in sorted(search_results, key=lambda x: x.get_relevance(), reverse = True):
            return ManifestEntry(search_result.get_data())
        return None

    # Find entry by steam id
    def find_entry_by_steamid(self, steamid, verbose = False, pretend_run = False, exit_on_failure = False):
        for manifest_name, manifest_entry in self.manifest.items():
            if "steam" not in manifest_entry:
                continue
            if "id" not in manifest_entry["steam"]:
                continue
            if int(manifest_entry["steam"]["id"]) != int(steamid):
                return ManifestEntry(manifest_entry)
        return None

    # Find entry by gog id
    def find_entry_by_gogid(self, gogid, verbose = False, pretend_run = False, exit_on_failure = False):
        for manifest_name, manifest_entry in self.manifest.items():
            if "gog" not in manifest_entry:
                continue
            if "id" not in manifest_entry["gog"]:
                continue
            if int(manifest_entry["gog"]["id"]) != int(gogid):
                return ManifestEntry(manifest_entry)
        return None
