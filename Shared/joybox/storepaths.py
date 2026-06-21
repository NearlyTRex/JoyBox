# Local imports
import joybox.config as config
import joybox.paths as paths

# Create tokenized path
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
    new_path = new_path.replace("<storeUserId>", config.token_store_user_id)
    new_path = new_path.replace("<winPublic>", config.token_user_public_dir)
    new_path = new_path.replace("<winDir>", config.token_user_profile_dir + "/AppData/Local/VirtualStore")
    new_path = new_path.replace("<winAppData>", config.token_user_profile_dir + "/AppData/Roaming")
    new_path = new_path.replace("<winAppDataLocalLow>", config.token_user_profile_dir + "/AppData/LocalLow")
    new_path = new_path.replace("<winLocalAppData>", config.token_user_profile_dir + "/AppData/Local")
    new_path = new_path.replace("<winProgramData>", config.token_user_profile_dir + "/AppData/Local/VirtualStore")
    new_path = new_path.replace("<winDocuments>", config.token_user_profile_dir + "/Documents")
    new_path = new_path.replace("<home>", config.token_user_profile_dir)
    new_path = new_path.replace("<root>", config.token_store_install_dir)
    if paths.is_path_valid(base_path):
        new_path = new_path.replace("<base>", base_path)
    else:
        new_path = new_path.replace("<base>", config.token_game_install_dir)

    # Return path
    return paths.normalize_file_path(new_path)
