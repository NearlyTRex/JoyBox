# Local imports
from joybox import config
from joybox import logger
from joybox import toolbase
from joybox import settings


# Moonlight tool
class Moonlight(toolbase.ToolBase):

    NAME = "Moonlight"

    # Write its config files under the tools root, and add or remove its app menu
    # entry by the Tools.Moonlight moonlight_client setting
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if not self.write_config_files(setup_params):
            return False

        # Put it in the app menu on a machine whose streaming role uses it
        return self.set_menu_launcher(
            enabled = settings.get_bool_value("Tools.Moonlight", "moonlight_client", False, throw_exception = False),
            filename = "joybox-moonlight.desktop",
            description = "Play games streamed from the Sunshine host",
            command_name = "launch_moonlight",
            icon = "input-gaming",
            setup_params = setup_params)


###########################################################
# Launching
###########################################################

# The Moonlight command line: pair with or list the host, stream the app from it when both are
# known, or else open Moonlight's host list
def build_moonlight_command(moonlight_tool, host = None, app = None, pair = False, list_apps = False):
    launch_cmd = [moonlight_tool]
    if pair:
        launch_cmd += ["pair", host]
    elif list_apps:
        launch_cmd += ["list", host]
    elif host and app:
        launch_cmd += ["stream", host, app]
    return launch_cmd

# Start Moonlight streaming the given or configured host and app, or pair with or list the host;
# quits when the options conflict, a host is needed but missing, or Moonlight fails
def launch_moonlight(host = None, app = None, pair = False, list_apps = False, verbose = False, pretend_run = False, exit_on_failure = False):
    moonlight_tool = Moonlight().get_installed_program()
    host = host or settings.get_value("Tools.Moonlight", "moonlight_host", "", throw_exception = False)
    app = app or settings.get_value("Tools.Moonlight", "moonlight_app", "", throw_exception = False)
    if pair and list_apps:
        logger.log_error("--pair and --list cannot be combined", quit_program = True)
    if (pair or list_apps) and not host:
        logger.log_error("%s needs a host, from --host or [Tools.Moonlight] moonlight_host" % (
            "Pairing" if pair else "Listing apps"), quit_program = True)
    Moonlight().run_launch_command(
        build_moonlight_command(moonlight_tool, host, app, pair = pair, list_apps = list_apps),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
