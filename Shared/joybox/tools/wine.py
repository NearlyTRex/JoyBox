# Local imports
import joybox.environment as environment
import joybox.toolbase as toolbase
import joybox.settings as settings
import joybox.paths as paths

# Config files
config_files = {}

# Wine tool
class Wine(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Wine"

    # Get config
    def get_config(self):

        # Check platform
        if not environment.is_wine_platform():
            return {}

        # Get wine info
        wine_exe = settings.get_value("Tools.Wine", "wine_exe")
        wine_boot_exe = settings.get_value("Tools.Wine", "wine_boot_exe")
        wine_server_exe = settings.get_value("Tools.Wine", "wine_server_exe")
        wine_tricks_exe = settings.get_value("Tools.Wine", "wine_tricks_exe")
        wine_install_dir = settings.get_path_value("Tools.Wine", "wine_install_dir")
        wine_sandbox_dir = settings.get_path_value("Tools.Wine", "wine_sandbox_dir")

        # Return config
        return {

            # Wine
            "Wine": {
                "program": paths.join_paths(wine_install_dir, wine_exe),
                "sandbox_dir": wine_sandbox_dir
            },

            # WineBoot
            "WineBoot": {
                "program": paths.join_paths(wine_install_dir, wine_boot_exe)
            },

            # WineServer
            "WineServer": {
                "program": paths.join_paths(wine_install_dir, wine_server_exe)
            },

            # WineTricks
            "WineTricks": {
                "program": paths.join_paths(wine_install_dir, wine_tricks_exe)
            }
        }
