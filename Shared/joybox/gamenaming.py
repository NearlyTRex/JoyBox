# Imports
import re

# Local imports
from joybox import config
from joybox import paths
from joybox import platforms
from joybox import strings
from joybox import text

# Derive game letter from name
def derive_game_letter_from_name(game_name):
    letter = ""
    if len(game_name):
        letter = game_name[0].upper()
    if letter.isnumeric():
        letter = config.GENERAL_FOLDER_NUMERIC
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

# Derive regular name from game name
def derive_regular_name_from_game_name(game_name, custom_prefix = "", custom_suffix = ""):
    regular_name = game_name
    for flippable_word in config.flippable_words:
        segment_before = f", {flippable_word} "
        segment_after = f"{flippable_word} "
        if segment_before in regular_name:
            regular_name = regular_name.replace(segment_before, " ")
            regular_name = segment_after + regular_name
    regular_name = re.sub(r"\((.*?)\)", "", regular_name).strip()
    regular_name = f"{custom_prefix}{regular_name}{custom_suffix}"
    return regular_name

# Derive game name from regular name
def derive_game_name_from_regular_name(regular_name, region="USA"):
    game_name = regular_name.strip()
    game_name = game_name.replace(":", " -")
    game_name = game_name.replace("&", "and")
    game_name = re.sub(r"-?\s*CE$", " Collector's Edition", game_name)
    game_name = text.clean_rich_text(game_name)
    game_name = text.capitalize_text(game_name)
    game_name = paths.replace_invalid_path_characters(game_name)
    for flippable_word in config.flippable_words:
        if game_name.startswith(f"{flippable_word} "):
            base_name = game_name[len(flippable_word) + 1:]
            if " - " in base_name:
                first_part, second_part = base_name.split(" - ", 1)
                game_name = f"{first_part.strip()}, {flippable_word} - {second_part.strip()}"
            else:
                game_name = f"{base_name}, {flippable_word}"
            break
    return f"{game_name} ({region})"

# Derive slug name from regular name
def derive_slug_name_from_regular_name(regular_name):
    return strings.get_slug_string(regular_name)

# Derive slug name from game name
def derive_slug_name_from_game_name(game_name, custom_prefix = "", custom_suffix = ""):
    regular_name = derive_regular_name_from_game_name(game_name, custom_prefix, custom_suffix)
    return derive_slug_name_from_regular_name(regular_name)

# Derive game search terms from name
def derive_game_search_terms_from_name(game_name, game_platform, custom_prefix = "", custom_suffix = ""):
    regular_name = derive_regular_name_from_game_name(game_name, custom_prefix, custom_suffix)
    return strings.encode_url_string(regular_name, use_plus = True)
