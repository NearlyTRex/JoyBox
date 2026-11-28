# Local imports
from joybox import config
from joybox import paths

# Rewrite a store or manifest save path's placeholders into JoyBox path tokens
# Install-dir placeholders become base_path when valid, else the game install token
def create_tokenized_path(path, base_path = None):

    # Replace tokens
    new_path = path
    new_path = new_path.replace("{EpicID}", "<storeUserId>")
    new_path = new_path.replace("{EpicId}", "<storeUserId>")
    new_path = new_path.replace("{UserDir}", "<home>")
    new_path = new_path.replace("{UserProfile}", "<home>")
    new_path = new_path.replace("%USERPROFILE%", "<home>")
    new_path = new_path.replace("%userprofile%", "<home>")
    new_path = new_path.replace("{InstallDir}", "<base>")
    new_path = new_path.replace("{UserSavedGames}", "<home>/Saved Games")
    new_path = new_path.replace("{AppData}/../Roaming", "<winAppData>")
    new_path = new_path.replace("{AppData}/../Roaming".lower(), "<winAppData>")
    new_path = new_path.replace("{AppData}/../LocalLow", "<winAppDataLocalLow>")
    new_path = new_path.replace("{AppData}/../LocalLow".lower(), "<winAppDataLocalLow>")
    new_path = new_path.replace("{AppData}", "<winLocalAppData>")
    new_path = new_path.replace("<storeUserId>", config.TOKEN_STORE_USER_ID)
    new_path = new_path.replace("<winPublic>", config.TOKEN_USER_PUBLIC_DIR)
    new_path = new_path.replace("<winDir>", config.TOKEN_USER_PROFILE_DIR + "/AppData/Local/VirtualStore")
    new_path = new_path.replace("<winAppData>", config.TOKEN_USER_PROFILE_DIR + "/AppData/Roaming")
    new_path = new_path.replace("<winAppDataLocalLow>", config.TOKEN_USER_PROFILE_DIR + "/AppData/LocalLow")
    new_path = new_path.replace("<winLocalAppData>", config.TOKEN_USER_PROFILE_DIR + "/AppData/Local")
    new_path = new_path.replace("<winProgramData>", config.TOKEN_USER_PROFILE_DIR + "/AppData/Local/VirtualStore")
    new_path = new_path.replace("<winDocuments>", config.TOKEN_USER_PROFILE_DIR + "/Documents")
    new_path = new_path.replace("<home>", config.TOKEN_USER_PROFILE_DIR)
    new_path = new_path.replace("<root>", config.TOKEN_STORE_INSTALL_DIR)
    if paths.is_path_valid(base_path):
        new_path = new_path.replace("<base>", base_path)
    else:
        new_path = new_path.replace("<base>", config.TOKEN_GAME_INSTALL_DIR)

    # Return path
    return paths.normalize_file_path(new_path)
