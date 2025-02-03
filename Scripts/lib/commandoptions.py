# Imports
import os, os.path
import sys
import copy

# Local imports
import config
import system
import ini

# Command options
class CommandOptions:

    # Constructor
    def __init__(
        self,
        cwd = None,
        env = None,
        shell = False,
        is_32_bit = False,
        is_dos = False,
        is_win31 = False,
        is_scumm = False,
        allow_processing = True,
        force_powershell = False,
        force_appimage = False,
        force_prefix = False,
        is_wine_prefix = False,
        is_sandboxie_prefix = False,
        is_prefix_mapped_cwd = False,
        prefix_dir = None,
        general_prefix_dir = None,
        prefix_user_profile_dir = None,
        prefix_c_drive_virtual = None,
        prefix_c_drive_real = None,
        prefix_name = None,
        prefix_winver = None,
        prefix_cwd = None,
        prefix_tricks = None,
        prefix_overrides = None,
        prefix_desktop_width = None,
        prefix_desktop_height = None,
        prefix_use_virtual_desktop = False,
        lnk_base_path = None,
        output_paths = [],
        blocking_processes = [],
        creationflags = 0,
        stdout = None,
        stderr = None,
        include_stderr = False):

        # Core
        self.cwd = cwd
        if env:
            self.env = env
        else:
            self.env = copy.deepcopy(os.environ)
        self.shell = shell
        self.is_32_bit = is_32_bit

        # Flags
        self.allow_processing = allow_processing
        self.force_powershell = force_powershell
        self.force_appimage = force_appimage
        self.force_prefix = force_prefix

        # Prefix
        self.is_dos = is_dos
        self.is_win31 = is_win31
        self.is_scumm = is_scumm
        self.is_wine_prefix = is_wine_prefix
        self.is_sandboxie_prefix = is_sandboxie_prefix
        self.is_prefix_mapped_cwd = is_prefix_mapped_cwd
        self.prefix_dir = prefix_dir
        self.general_prefix_dir = general_prefix_dir
        self.prefix_user_profile_dir = prefix_user_profile_dir
        self.prefix_c_drive_virtual = prefix_c_drive_virtual
        self.prefix_c_drive_real = prefix_c_drive_real
        self.prefix_name = prefix_name
        self.prefix_winver = prefix_winver
        self.prefix_cwd = prefix_cwd
        self.prefix_tricks = prefix_tricks
        self.prefix_overrides = prefix_overrides
        self.prefix_desktop_width = prefix_desktop_width
        self.prefix_desktop_height = prefix_desktop_height
        self.prefix_use_virtual_desktop = prefix_use_virtual_desktop

        # Other
        self.lnk_base_path = lnk_base_path
        self.output_paths = output_paths
        self.blocking_processes = blocking_processes
        self.creationflags = creationflags
        self.stdout = stdout
        self.stderr = stderr
        self.include_stderr = include_stderr

    # Copy method
    def copy(self):
        return copy.deepcopy(self)

    ###########################################################
    # Core
    ###########################################################

    # Working directory
    def get_cwd(self):
        return self.cwd
    def set_cwd(self, value):
        self.cwd = value
    def has_valid_cwd(self):
        return system.IsPathValid(self.cwd)

    # Environment variables
    def get_env(self):
        return self.env
    def set_env(self, value):
        self.env = value
    def add_env(self, key, value):
        self.env[key] = value

    # Shell execution
    def get_shell(self):
        return self.shell
    def set_shell(self, value):
        self.shell = value

    # 32-bit execution
    def is_32_bit(self):
        return self.is_32_bit
    def set_is_32_bit(self, value):
        self.is_32_bit = value

    ###########################################################
    # Flags
    ###########################################################

    # Allow processing
    def get_allow_processing(self):
        return self.allow_processing
    def set_allow_processing(self, value):
        self.allow_processing = value

    # Force powershell
    def get_force_powershell(self):
        return self.force_powershell
    def set_force_powershell(self, value):
        self.force_powershell = value

    # Force AppImage
    def get_force_appimage(self):
        return self.force_appimage
    def set_force_appimage(self, value):
        self.force_appimage = value

    ###########################################################
    # Prefix
    ###########################################################

    # Dos execution
    def is_dos(self):
        return self.is_dos
    def set_is_dos(self, value):
        self.is_dos = value

    # Windows 3.1 execution
    def is_win31(self):
        return self.is_win31
    def set_is_win31(self, value):
        self.is_win31 = value

    # Scumm execution
    def is_scumm(self):
        return self.is_scumm
    def set_is_scumm(self, value):
        self.is_scumm = value

    # Force prefix
    def get_force_prefix(self):
        return self.force_prefix
    def set_force_prefix(self, value):
        self.force_prefix = value

    # Wine prefix
    def is_wine_prefix(self):
        return self.is_wine_prefix
    def set_is_wine_prefix(self, value):
        self.is_wine_prefix = value

    # Sandboxie prefix
    def is_sandboxie_prefix(self):
        return self.is_sandboxie_prefix
    def set_is_sandboxie_prefix(self, value):
        self.is_sandboxie_prefix = value

    # Working dir prefix mapping
    def is_prefix_mapped_cwd(self):
        return self.is_prefix_mapped_cwd
    def set_is_prefix_mapped_cwd(self, value):
        self.is_prefix_mapped_cwd = value

    # Prefix dir
    def get_prefix_dir(self):
        return self.prefix_dir
    def set_prefix_dir(self, value):
        self.prefix_dir = value
    def has_valid_prefix_dir(self):
        return system.IsPathValid(self.prefix_dir)
    def has_existing_prefix_dir(self):
        return system.DoesPathExist(self.prefix_dir)

    # General prefix dir
    def get_general_prefix_dir(self):
        return self.general_prefix_dir
    def set_general_prefix_dir(self, value):
        self.general_prefix_dir = value
    def has_valid_general_prefix_dir(self):
        return system.IsPathValid(self.general_prefix_dir)
    def has_existing_general_prefix_dir(self):
        return system.DoesPathExist(self.prefix_dir)

    # Prefix user profile dir
    def get_prefix_user_profile_dir(self):
        return self.prefix_user_profile_dir
    def set_prefix_user_profile_dir(self, value):
        self.prefix_user_profile_dir = value
    def has_valid_prefix_user_profile_dir(self):
        return system.IsPathValid(self.prefix_user_profile_dir)
    def has_existing_prefix_user_profile_dir(self):
        return system.DoesPathExist(self.prefix_user_profile_dir)

    # Prefix c drive virtual
    def get_prefix_c_drive_virtual(self):
        return self.prefix_c_drive_virtual
    def set_prefix_c_drive_real(self, value):
        self.prefix_c_drive_virtual = value
    def has_valid_prefix_c_drive_virtual(self):
        return system.IsPathValid(self.prefix_c_drive_virtual)

    # Prefix c drive real
    def get_prefix_c_drive_real(self):
        return self.prefix_c_drive_real
    def set_prefix_c_drive_real(self, value):
        self.prefix_c_drive_real = value
    def has_valid_prefix_c_drive_real(self):
        return system.IsPathValid(self.prefix_c_drive_real)
    def has_existing_prefix_c_drive_real(self):
        return system.DoesPathExist(self.prefix_c_drive_real)

    # Prefix dos c drive
    def get_prefix_dos_c_drive(self):
        if self.has_valid_prefix_c_drive_real():
            return system.JoinPaths(self.get_prefix_c_drive_real(), config.computer_folder_dos, "C")
        return None
    def has_valid_prefix_dos_c_drive(self):
        return system.IsPathValid(self.get_prefix_dos_c_drive())

    # Prefix dos d drive
    def get_prefix_dos_d_drive(self):
        if self.has_valid_prefix_c_drive_real():
            return system.JoinPaths(self.get_prefix_c_drive_real(), config.computer_folder_dos, "D")
        return None
    def has_valid_prefix_dos_d_drive(self):
        return system.IsPathValid(self.get_prefix_dos_d_drive())

    # Prefix name
    def get_prefix_name(self):
        return self.prefix_name
    def set_prefix_name(self, value):
        self.prefix_name = value

    # Prefix windows version
    def get_prefix_winver(self):
        return self.prefix_winver
    def set_prefix_winver(self, value):
        self.prefix_winver = value

    # Prefix working directory
    def get_prefix_cwd(self):
        return self.prefix_cwd
    def set_prefix_cwd(self, value):
        self.prefix_cwd = value

    # Prefix tricks
    def get_prefix_tricks(self):
        tricks = []
        if isinstance(self.prefix_winver, str):
            tricks += [self.prefix_winver]
        if isinstance(self.prefix_tricks, list):
            tricks += self.prefix_tricks
        return tricks

    # Prefix overrides
    def get_prefix_overrides(self):
        if isinstance(self.prefix_overrides, list):
            return self.prefix_overrides
        return []

    # Prefix desktop width
    def get_prefix_desktop_width(self):
        if self.prefix_desktop_width:
            return self.prefix_desktop_width
        return ini.GetIniValue("UserData.Resolution", "screen_resolution_w")
    def set_prefix_desktop_width(self, value):
        self.prefix_desktop_width = value

    # Prefix desktop height
    def get_prefix_desktop_height(self):
        if self.prefix_desktop_height:
            return self.prefix_desktop_height
        return ini.GetIniValue("UserData.Resolution", "screen_resolution_h")
    def set_prefix_desktop_height(self, value):
        self.prefix_desktop_height = value

    # Prefix desktop dimensions
    def get_prefix_desktop_dimensions(self):
        return "%sx%s" % (self.get_prefix_desktop_width(), self.get_prefix_desktop_height())

    ###########################################################
    # Other
    ###########################################################

    # Link base path
    def get_lnk_base_path(self):
        return self.lnk_base_path
    def set_lnk_base_path(self, value):
        self.lnk_base_path = value

    # Output paths
    def get_output_paths(self):
        return self.output_paths
    def set_output_paths(self, value):
        self.output_paths = value

    # Blocking processes
    def get_blocking_processes(self):
        return self.blocking_processes
    def set_blocking_processes(self, value):
        self.blocking_processes = value

    # Creation flags
    def get_creationflags(self):
        return self.creationflags
    def set_creationflags(self, value):
        self.creationflags = value

    # Stdout
    def get_stdout(self):
        return self.stdout
    def set_stdout(self, value):
        self.stdout = value

    # Stderr
    def get_stderr(self):
        return self.stderr
    def set_stderr(self, value):
        self.stderr = value

    # Include stderr in stdout
    def include_stderr(self):
        return self.include_stderr
    def set_include_stderr(self, value):
        self.include_stderr = value
