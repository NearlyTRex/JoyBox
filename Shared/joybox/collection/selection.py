# Local imports
from joybox import config
from joybox import gamecollection

# Every ROM (supercategory, category, subcategory) in the chosen categories, kept to the chosen
# subcategories when any are given; all categories when none are
def iterate_selected_subcategories(categories = None, subcategories = None):
    game_supercategory = config.Supercategory.ROMS
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    selected_subcategories = config.Subcategory.from_list(subcategories) if subcategories else None
    for game_category in selected_categories:
        category_subcategories = config.subcategory_map[game_category]
        if selected_subcategories:
            category_subcategories = [sc for sc in category_subcategories if sc in selected_subcategories]
        for game_subcategory in category_subcategories:
            yield game_supercategory, game_category, game_subcategory

# Every json game in the selected categories, as (supercategory, category, subcategory, name)
def iterate_selected_json_games(categories = None, subcategories = None, locker_type = None):
    for game_supercategory, game_category, game_subcategory in iterate_selected_subcategories(categories, subcategories):
        for game_name in gamecollection.find_json_game_names(game_supercategory, game_category, game_subcategory, locker_type):
            yield game_supercategory, game_category, game_subcategory, game_name

# Every locker game in the selected categories, as (supercategory, category, subcategory, name)
def iterate_selected_locker_games(categories = None, subcategories = None, locker_type = None):
    for game_supercategory, game_category, game_subcategory in iterate_selected_subcategories(categories, subcategories):
        for game_name in gamecollection.find_locker_game_names(game_supercategory, game_category, game_subcategory, locker_type):
            yield game_supercategory, game_category, game_subcategory, game_name
