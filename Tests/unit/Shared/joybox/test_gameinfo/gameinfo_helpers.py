# Imports
import json
import os

# Local imports
from joybox import config, environment

SUPERCATEGORY = config.Supercategory.ROMS
CATEGORY = config.Category.NINTENDO
SUBCATEGORY = config.Subcategory.NINTENDO_NES
GAME = "Chrono Trigger (USA)"


# Write a game's json file where GameInfo looks for it
def write_game(tree, data = None, name = GAME,
               supercategory = SUPERCATEGORY, category = CATEGORY, subcategory = SUBCATEGORY):
    target = environment.get_game_json_metadata_file(
        supercategory, category, subcategory, name)
    os.makedirs(os.path.dirname(target), exist_ok = True)
    with open(target, "w") as handle:
        handle.write(json.dumps(data if data is not None else {}))
    return target
