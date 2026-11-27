# Local imports
from joybox import config
from joybox import command
from joybox import programs
from joybox import logger
from joybox import paths
from joybox import environment
from joybox import fileops
from joybox import toolbase
from joybox import desktopentry
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
        for config_filename, config_contents in self.get_config_files().items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Moonlight config files")
                return False

        # Put it in the app menu on a machine whose streaming role uses it
        success = desktopentry.set_launcher(
            enabled = settings.get_bool_value("Tools.Moonlight", "moonlight_client", False, throw_exception = False),
            filename = "joybox-moonlight.desktop",
            name = "Moonlight",
            description = "Play games streamed from the Sunshine host",
            command = "launch_moonlight",
            icon = "input-gaming",
            verbose = setup_params.verbose,
            pretend_run = setup_params.pretend_run,
            exit_on_failure = setup_params.exit_on_failure)
        if not success:
            logger.log_error("Could not setup the Moonlight launcher")
            return False
        return True


###########################################################
# Launching
###########################################################

# The installed Moonlight program, quitting with an error when it is missing
def get_moonlight_program():
    moonlight_tool = None
    if programs.is_tool_installed("Moonlight"):
        moonlight_tool = programs.get_tool_program("Moonlight")
    if not moonlight_tool:
        logger.log_error("Moonlight was not found", quit_program = True)
    return moonlight_tool

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
    moonlight_tool = get_moonlight_program()
    host = host or settings.get_value("Tools.Moonlight", "moonlight_host", "", throw_exception = False)
    app = app or settings.get_value("Tools.Moonlight", "moonlight_app", "", throw_exception = False)
    if pair and list_apps:
        logger.log_error("--pair and --list cannot be combined", quit_program = True)
    if (pair or list_apps) and not host:
        logger.log_error("%s needs a host, from --host or [Tools.Moonlight] moonlight_host" % (
            "Pairing" if pair else "Listing apps"), quit_program = True)
    code = command.run_returncode_command(
        cmd = build_moonlight_command(moonlight_tool, host, app, pair = pair, list_apps = list_apps),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Launch command failed with code %d" % code, quit_program = True)
