# Local imports
import joybox.config as config
import joybox.platforms as platforms
import joybox.paths as paths

# Derive game letter from name
def derive_game_letter_from_name(game_name):
    letter = ""
    if len(game_name):
        letter = game_name[0].upper()
    if letter.isnumeric():
        letter = config.general_folder_numeric
    return letter

# Derive game name path from name
def derive_game_name_path_from_name(game_name, game_platform):
    if platforms.is_letter_platform(game_platform):
        return paths.join_paths(derive_game_letter_from_name(game_name), game_name)
    else:
        return game_name

# Derive game platform from categories
def derive_game_platform_from_categories(game_category, game_subcategory):
    for game_platform in config.Platform.members():
        if game_platform.val().endswith(game_subcategory.val()):
            return game_platform
    return None

# Derive game asset path from name
def derive_game_asset_path_from_name(game_name, asset_type):
    return "%s/%s%s" % (asset_type.val(), game_name, asset_type.cval())

# Derive game categories from platform
def derive_game_categories_from_platform(game_platform):
    if not game_platform:
        return (None, None, None)
    derived_supercategory = config.Supercategory.ROMS
    derived_category = None
    derived_subcategory = None
    for game_category in config.Category.members():
        if game_platform.name.startswith(game_category.name):
            derived_category = game_category
    for game_subcategory in config.Subcategory.members():
        if game_platform.name.startswith(game_subcategory.name):
            derived_subcategory = game_subcategory
    return (derived_supercategory, derived_category, derived_subcategory)
