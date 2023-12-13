# Imports
import os, os.path
import sys

# Local imports
import config
import command
import programs

# Get current screen resolution
def GetCurrentScreenResolution():
    import screeninfo
    for monitor in screeninfo.get_monitors():
        if monitor.is_primary:
            return (monitor.width, monitor.height)
    return (0, 0)

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

    # Get resolution info
    screen_resolution_w = ini.GetIniIntegerValue("UserData.Resolution", "screen_resolution_w")
    screen_resolution_h = ini.GetIniIntegerValue("UserData.Resolution", "screen_resolution_h")
    screen_resolution_c = ini.GetIniIntegerValue("UserData.Resolution", "screen_resolution_c")

    # Ignore if already at the default resolution
    current_w, current_h = GetCurrentScreenResolution()
    is_default_w = (current_w == screen_resolution_w)
    is_default_h = (current_h == screen_resolution_h)
    if is_default_w and is_default_h:
        return True

    # Set the new resolution otherwise
    return SetScreenResolution(
        width = screen_resolution_w,
        height = screen_resolution_h,
        colors = screen_resolution_c,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
