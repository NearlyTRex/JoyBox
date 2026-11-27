# Local imports
from joybox import command
from joybox import commandbase
from joybox import gui
from joybox import programs
from joybox import settings

# Switch the display mode through NirCmd setdisplay; False only when NirCmd is missing
def set_screen_resolution(width, height, colors, verbose = False, pretend_run = False, exit_on_failure = False):

    # Get tool
    nircmd_tool = programs.find_tool_program("NirCmd")
    if not nircmd_tool:
        return False

    # Get resolution command
    resolution_cmd = [
        nircmd_tool,
        "setdisplay",
        str(width),
        str(height),
        str(colors)
    ]

    # Set resolution
    command.run_returncode_command(
        cmd = resolution_cmd,
        options = commandbase.create_command_options(
            is_shell = True),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

# Return to the resolution the UserData.Resolution settings name, unless the screen is already at it
def restore_default_screen_resolution(verbose = False, pretend_run = False, exit_on_failure = False):

    # Get resolution info
    screen_resolution_w = settings.get_integer_value("UserData.Resolution", "screen_resolution_w")
    screen_resolution_h = settings.get_integer_value("UserData.Resolution", "screen_resolution_h")
    screen_resolution_c = settings.get_integer_value("UserData.Resolution", "screen_resolution_c")

    # Ignore if already at the default resolution
    current_w, current_h = gui.get_current_screen_resolution()
    is_default_w = current_w == screen_resolution_w
    is_default_h = current_h == screen_resolution_h
    if is_default_w and is_default_h:
        return True

    # Set the new resolution otherwise
    return set_screen_resolution(
        width = screen_resolution_w,
        height = screen_resolution_h,
        colors = screen_resolution_c,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
