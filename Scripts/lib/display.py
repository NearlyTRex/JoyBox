# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import programs

# Get current screen resolution
def GetCurrentScreenResolution():

    # Linux
    if IsLinuxPlatform():
        output = command.RunOutputCommand(
            cmd = ["xdpyinfo"],
            options = command.CommandOptions(shell = True))
        for line in output.split("\n"):
            if "dimensions:" in line:
                line_tokens = line.split()
                if len(line_tokens) < 2:
                    continue
                dimensions = line_tokens[1].split("x")
                return (int(dimensions[0]), int(dimensions[1]))

    # Other
    else:
        import pyautogui
        size = pyautogui.size()
        return (size.width, size.height)

# Set screen resolution
def SetScreenResolution(width, height, colors, verbose = False, exit_on_failure = False):

    # Get tool
    nircmd_tool = None
    if programs.IsToolInstalled("NirCmd"):
        nircmd_tool = programs.GetToolProgram("NirCmd")
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
    command.RunBlockingCommand(
        cmd = resolution_cmd,
        options = command.CommandOptions(
            shell = True),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return True

# Restore default screen resolution
def RestoreDefaultScreenResolution(verbose = False, exit_on_failure = False):

    # Ignore if already at the default resolution
    current_w, current_h = GetCurrentScreenResolution()
    is_default_w = (current_w == config.default_screen_resolution_w)
    is_default_h = (current_h == config.default_screen_resolution_h)
    if is_default_w and is_default_h:
        return True

    # Set the new resolution otherwise
    return SetScreenResolution(
        width = config.default_screen_resolution_w,
        height = config.default_screen_resolution_h,
        colors = config.default_screen_resolution_c,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
