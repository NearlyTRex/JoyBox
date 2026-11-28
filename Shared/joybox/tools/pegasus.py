# Local imports
from joybox import config
from joybox import paths
from joybox import environment
from joybox import toolbase

# Every dir under the Pegasus metadata root that holds a metadata.pegasus.txt
def get_game_dirs():
    game_dirs = []
    for pegasus_file in paths.build_file_list_by_extensions(environment.get_game_pegasus_metadata_root_dir(), extensions = [".txt"]):
        if pegasus_file.endswith("metadata.pegasus.txt"):
            game_dirs.append(paths.get_filename_directory(pegasus_file))
    return game_dirs

# Pegasus tool
class Pegasus(toolbase.ToolBase):

    NAME = "Pegasus"

    # Write its config files with game_dirs.txt listing every dir that holds a metadata.pegasus.txt,
    # then add its app menu entry
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Generate game dirs
        game_dirs = get_game_dirs()

        # Update game dir files
        config_files = self.get_config_files()
        config_files["Pegasus/windows/config/game_dirs.txt"] = "\n".join(game_dirs)
        config_files["Pegasus/linux/Pegasus.AppImage.home/.config/pegasus-frontend/game_dirs.txt"] = "\n".join(game_dirs)

        # Create config files
        if not self.write_config_files(setup_params, config_files):
            return False

        # Put it in the app menu
        return self.set_menu_launcher(
            enabled = True,
            filename = "joybox-pegasus.desktop",
            description = "Browse and launch the game collection",
            command_name = "launch_pegasus",
            icon = "applications-games",
            setup_params = setup_params)
