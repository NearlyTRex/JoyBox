# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import environment
import programs
import image
import ini

# Get search results
def GetSearchResults(
    search_terms,
    image_dimensions = None,
    image_types = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get authorization info
    steamgriddb_api_key = ini.GetIniValue("UserData.Scraping", "steamgriddb_api_key")

    # Import steamgrid
    steamgrid = environment.ImportPythonModulePackage(
        module_path = programs.GetToolPathConfigValue("PySteamGridDB", "package_dir"),
        module_name = programs.GetToolConfigValue("PySteamGridDB", "package_name"))

    # Create image links
    image_links = []

    # Initialize client
    sgdb = steamgrid.SteamGridDB(steamgriddb_api_key)

    # Search for the image links
    search_results = sgdb.search_game(search_terms)
    for search_result in search_results:
        search_grids = sgdb.get_grids_by_gameid(game_ids=[search_result.id])
        if system.IsIterableContainer(search_grids):
            for search_grid in search_grids:

                # Ignore images that do not match requested dimensions
                if system.IsIterableNonString(image_dimensions) and len(image_dimensions) == 2:
                    requested_w = image_dimensions[0]
                    requested_h = image_dimensions[1]
                    if search_grid.width != requested_w:
                        continue
                    if search_grid.height != requested_h:
                        continue

                # Ignore images that do not match requested types
                if system.IsIterableNonString(image_types) and len(image_types) > 0:
                    found_type = image.GetImageFormat(search_grid.url)
                    if found_type and found_type not in image_types:
                        continue

                # Add image link
                search_grid_dict = search_grid.to_json()
                search_grid_dict["id"] = search_result.id
                search_grid_dict["name"] = search_result.name
                search_grid_dict["release_date"] = search_result.release_date
                search_grid_dict["types"] = search_result.types
                search_grid_dict["relevance"] = system.GetStringSimilarityRatio(search_terms, search_result.name)
                image_links.append(search_grid_dict)

    # Return image links
    return sorted(image_links, key=lambda x: x["relevance"], reverse = True)
