# Imports
import os, os.path
import sys
import copy

# Local imports
import config
import system
import jsondata
import paths
import ini
import sandbox

# Command options
class CommandOptions:

    # Constructor
    def __init__(self, **kwargs):
        self.options = jsondata.JsonData()
        for key, value in kwargs.items():
            self.options.set_value(key, value)

    # Copy method
    def copy(self):
        return copy.deepcopy(self)

    ###########################################################
    # Core
    ###########################################################

    # Working directory
    def get_cwd(self):
        return self.options.get_value(config.program_key_cwd)
    def set_cwd(self, value):
        self.options.set_value(config.program_key_cwd, value)
    def has_valid_cwd(self):
        return paths.is_path_valid(self.options.get_value(config.program_key_cwd))

    # Environment variables
    def get_env(self):
        return self.options.get_value(config.program_key_env, copy.deepcopy(os.environ))
    def set_env(self, value):
        self.options.set_value(config.program_key_env, value)
    def get_env_var(self, key):
        return self.options.get_subvalue(config.program_key_env, key)
    def set_env_var(self, key, value):
        if not self.options.has_key(config.program_key_env):
            self.options.set_value(config.program_key_env, copy.deepcopy(os.environ))
        self.options.set_subvalue(config.program_key_env, key, value)

    # Arguments
    def get_args(self):
        return self.options.get_value(config.program_key_args, [])
    def set_args(self, value):
        self.options.set_value(config.program_key_args, value)

    # Windows version
    def get_winver(self):
        return self.options.get_value(config.program_key_winver)
    def set_winver(self, value):
        self.options.set_value(config.program_key_winver, value)

    # Tricks
    def get_tricks(self):
        tricks = []
        if isinstance(self.options.get_value(config.program_key_winver), str):
            tricks += [self.options.get_value(config.program_key_winver)]
        tricks += self.options.get_value(config.program_key_tricks, [])
        return tricks
    def set_tricks(self, value):
        self.options.set_value(config.program_key_tricks, value)

    # Overrides
    def get_overrides(self):
        return self.options.get_value(config.program_key_overrides, [])
    def set_overrides(self, value):
        self.options.set_value(config.program_key_overrides, value)

    # Desktop width
    def get_desktop_width(self):
        ini_default = ini.get_ini_value("UserData.Resolution", "screen_resolution_w")
        return self.options.get_value(config.program_key_desktop_width) or ini_default
    def set_desktop_width(self, value):
        self.options.set_value(config.program_key_desktop_width, value)

    # Desktop height
    def get_desktop_height(self):
        ini_default = ini.get_ini_value("UserData.Resolution", "screen_resolution_h")
        return self.options.get_value(config.program_key_desktop_height) or ini_default
    def set_desktop_height(self, value):
        self.options.set_value(config.program_key_desktop_height, value)

    # Desktop dimensions
    def get_desktop_dimensions(self):
        return "%sx%s" % (self.get_desktop_width(), self.get_desktop_height())

    # Installer type
    def get_installer_type(self):
        return self.options.get_value(config.program_key_installer_type)
    def set_installer_type(self, value):
        self.options.set_value(config.program_key_installer_type, value)

    # Serial
    def get_serial(self):
        return self.options.get_value(config.program_key_serial)
    def set_serial(self, value):
        self.options.set_value(config.program_key_serial, value)

    ###########################################################
    # Flags
    ###########################################################

    # Shell execution
    def is_shell(self):
        return self.options.get_value(config.program_key_is_shell, False)
    def set_is_shell(self, value):
        self.options.set_value(config.program_key_is_shell, value)

    # Daemon execution
    def is_daemon(self):
        return self.options.get_value(config.program_key_is_daemon, False)
    def set_is_daemon(self, value):
        self.options.set_value(config.program_key_is_daemon, value)

    # Suppress output
    def is_output_suppressed(self):
        return self.options.get_value(config.program_key_suppress_output, False)
    def set_suppress_output(self, value):
        self.options.set_value(config.program_key_suppress_output, value)

    # 32-bit execution
    def is_32_bit(self):
        return self.options.get_value(config.program_key_is_32_bit, False)
    def set_is_32_bit(self, value):
        self.options.set_value(config.program_key_is_32_bit, value)

    # Dos execution
    def is_dos(self):
        return self.options.get_value(config.program_key_is_dos, False)
    def set_is_dos(self, value):
        self.options.set_value(config.program_key_is_dos, value)

    # Windows 3.1 execution
    def is_win31(self):
        return self.options.get_value(config.program_key_is_win31, False)
    def set_is_win31(self, value):
        self.options.set_value(config.program_key_is_win31, value)

    # Scumm execution
    def is_scumm(self):
        return self.options.get_value(config.program_key_is_scumm, False)
    def set_is_scumm(self, value):
        self.options.set_value(config.program_key_is_scumm, value)

    # Allow processing
    def allow_processing(self):
        return self.options.get_value(config.program_key_allow_processing, True)
    def set_allow_processing(self, value):
        self.options.set_value(config.program_key_allow_processing, value)

    # Force powershell
    def force_powershell(self):
        return self.options.get_value(config.program_key_force_powershell, False)
    def set_force_powershell(self, value):
        self.options.set_value(config.program_key_force_powershell, value)

    # Force AppImage
    def force_appimage(self):
        return self.options.get_value(config.program_key_force_appimage, False)
    def set_force_appimage(self, value):
        self.options.set_value(config.program_key_force_appimage, value)

    # Use virtual desktop
    def use_virtual_desktop(self):
        return self.options.get_value(config.program_key_use_virtual_desktop, False)
    def set_use_virtual_desktop(self, value):
        self.options.set_value(config.program_key_use_virtual_desktop, value)

    ###########################################################
    # Prefix
    ###########################################################

    # Force prefix
    def force_prefix(self):
        return self.options.get_value(config.program_key_force_prefix, False)
    def set_force_prefix(self, value):
        self.options.set_value(config.program_key_force_prefix, value)

    # Wine prefix
    def is_wine_prefix(self):
        return self.options.get_value(config.program_key_is_wine_prefix, False)
    def set_is_wine_prefix(self, value):
        self.options.set_value(config.program_key_is_wine_prefix, value)

    # Sandboxie prefix
    def is_sandboxie_prefix(self):
        return self.options.get_value(config.program_key_is_sandboxie_prefix, False)
    def set_is_sandboxie_prefix(self, value):
        self.options.set_value(config.program_key_is_sandboxie_prefix, value)

    # General prefix
    def is_prefix(self):
        return self.is_wine_prefix() or self.is_sandboxie_prefix()

    # Prefix mapped current working directory
    def is_prefix_mapped_cwd(self):
        return self.options.get_value(config.program_key_is_prefix_mapped_cwd, False)
    def set_is_prefix_mapped_cwd(self, value):
        self.options.set_value(config.program_key_is_prefix_mapped_cwd, value)

    # Prefix dir
    def get_prefix_dir(self):
        return self.options.get_value(config.program_key_prefix_dir)
    def set_prefix_dir(self, value):
        self.options.set_value(config.program_key_prefix_dir, value)
    def has_valid_prefix_dir(self):
        return paths.is_path_valid(self.options.get_value(config.program_key_prefix_dir))
    def has_existing_prefix_dir(self):
        return paths.does_path_exist(self.options.get_value(config.program_key_prefix_dir))

    # General prefix dir
    def get_general_prefix_dir(self):
        return self.options.get_value(config.program_key_general_prefix_dir)
    def set_general_prefix_dir(self, value):
        self.options.set_value(config.program_key_general_prefix_dir, value)
    def has_valid_general_prefix_dir(self):
        return paths.is_path_valid(self.options.get_value(config.program_key_general_prefix_dir))
    def has_existing_general_prefix_dir(self):
        return paths.does_path_exist(self.options.get_value(config.program_key_general_prefix_dir))

    # Prefix user profile dir
    def get_prefix_user_profile_dir(self):
        return self.options.get_value(config.program_key_prefix_user_profile_dir)
    def set_prefix_user_profile_dir(self, value):
        self.options.set_value(config.program_key_prefix_user_profile_dir, value)
    def has_valid_prefix_user_profile_dir(self):
        return paths.is_path_valid(self.options.get_value(config.program_key_prefix_user_profile_dir))
    def has_existing_prefix_user_profile_dir(self):
        return paths.does_path_exist(self.options.get_value(config.program_key_prefix_user_profile_dir))

    # Prefix user profile game data directory
    def get_prefix_user_profile_gamedata_dir(self):
        if self.has_valid_prefix_user_profile_dir():
            return paths.join_paths(self.get_prefix_user_profile_dir(), config.computer_folder_gamedata)
        return None

    # Prefix user profile registry directory
    def get_prefix_user_profile_registry_dir(self):
        if self.has_valid_prefix_user_profile_dir():
            return paths.join_paths(self.get_prefix_user_profile_dir(), config.computer_folder_registry)
        return None

    # Prefix c drive virtual
    def get_prefix_c_drive_virtual(self):
        return self.options.get_value(config.program_key_prefix_c_drive_virtual)
    def set_prefix_c_drive_virtual(self, value):
        self.options.set_value(config.program_key_prefix_c_drive_virtual, value)
    def has_valid_prefix_c_drive_virtual(self):
        return paths.is_path_valid(self.options.get_value(config.program_key_prefix_c_drive_virtual))

    # Prefix c drive real
    def get_prefix_c_drive_real(self):
        return self.options.get_value(config.program_key_prefix_c_drive_real)
    def set_prefix_c_drive_real(self, value):
        self.options.set_value(config.program_key_prefix_c_drive_real, value)
    def has_valid_prefix_c_drive_real(self):
        return paths.is_path_valid(self.options.get_value(config.program_key_prefix_c_drive_real))
    def has_existing_prefix_c_drive_real(self):
        return paths.does_path_exist(self.options.get_value(config.program_key_prefix_c_drive_real))

    # Prefix dos c drive
    def get_prefix_dos_c_drive(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.computer_folder_dos, "C")
        return None
    def has_valid_prefix_dos_c_drive(self):
        return paths.is_path_valid(self.get_prefix_dos_c_drive())

    # Prefix dos d drive
    def get_prefix_dos_d_drive(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.computer_folder_dos, "D")
        return None
    def has_valid_prefix_dos_d_drive(self):
        return paths.is_path_valid(self.get_prefix_dos_d_drive())

    # Prefix scumm directory
    def get_prefix_scumm_dir(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.computer_folder_scumm)
        return None
    def has_valid_prefix_scumm_dir(self):
        return paths.is_path_valid(self.get_prefix_scumm_dir())

    # Prefix name
    def get_prefix_name(self):
        return self.options.get_value(config.program_key_prefix_name)
    def set_prefix_name(self, value):
        self.options.set_value(config.program_key_prefix_name, value)
    def has_prefix_name(self):
        return isinstance(self.get_prefix_name(), str) and len(self.get_prefix_name()) > 0

    # Prefix working directory
    def get_prefix_cwd(self):
        return self.options.get_value(config.program_key_prefix_cwd)
    def set_prefix_cwd(self, value):
        self.options.set_value(config.program_key_prefix_cwd, value)
    def has_valid_prefix_cwd(self):
        return paths.is_path_valid(self.get_prefix_cwd())
    def sync_cwd_to_prefix_cwd(self):
        if self.has_existing_prefix_c_drive_real() and self.has_valid_prefix_cwd():
            self.set_cwd(os.path.realpath(paths.join_paths(self.get_prefix_c_drive_real(), self.get_prefix_cwd)))

    # Ready prefix
    def has_ready_prefix(self):
        if not self.is_prefix():
            return False
        if not self.has_prefix_name():
            return False
        if not self.has_existing_prefix_dir():
            return False
        return True

    # Setup prefix
    def setup_prefix(
        self,
        is_wine_prefix,
        is_sandboxie_prefix,
        prefix_name,
        prefix_dir = None,
        general_prefix_dir = None):

        # Basic prefix info
        self.set_is_wine_prefix(is_wine_prefix)
        self.set_is_sandboxie_prefix(is_sandboxie_prefix)
        self.set_prefix_name(prefix_name)

        # Prefix dir
        if not paths.is_path_valid(prefix_dir):
            prefix_dir = sandbox.get_prefix(self)
        if paths.is_path_valid(prefix_dir):
            self.set_prefix_dir(prefix_dir)

        # General prefix dir
        if paths.is_path_valid(general_prefix_dir):
            self.set_general_prefix_dir(general_prefix_dir)

    # Create prefix
    def create_prefix(
        self,
        is_wine_prefix,
        is_sandboxie_prefix,
        prefix_name,
        prefix_dir = None,
        general_prefix_dir = None,
        linked_prefix = False,
        other_links = [],
        clean_existing = True,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Setup prefix
        self.setup_prefix(
            is_wine_prefix = is_wine_prefix,
            is_sandboxie_prefix = is_sandboxie_prefix,
            prefix_name = prefix_name,
            prefix_dir = prefix_dir,
            general_prefix_dir = general_prefix_dir)

        # Create prefix
        if linked_prefix:
            success = sandbox.create_linked_prefix(
                options = self,
                other_links = other_links,
                clean_existing = clean_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
        else:
            success = sandbox.create_basic_prefix(
                options = self,
                clean_existing = clean_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

        # Set prefix user profile dir
        self.set_prefix_user_profile_dir(sandbox.get_user_profile_path(self))
        if not self.has_existing_prefix_user_profile_dir():
            return False

        # Set prefix C drive
        self.set_prefix_c_drive_virtual(config.drive_root_windows)
        self.set_prefix_c_drive_real(sandbox.get_real_c_drive_path(self))
        if not self.has_existing_prefix_c_drive_real():
            return False

        # Should be successful
        return True

    ###########################################################
    # Other
    ###########################################################

    # Link base path
    def get_lnk_base_path(self):
        return self.options.get_value(config.program_key_lnk_base_path)
    def set_lnk_base_path(self, value):
        self.options.set_value(config.program_key_lnk_base_path, value)

    # Output paths
    def get_output_paths(self):
        return self.options.get_value(config.program_key_output_paths, [])
    def set_output_paths(self, value):
        self.options.set_value(config.program_key_output_paths, value)

    # Blocking processes
    def get_blocking_processes(self):
        return self.options.get_value(config.program_key_blocking_processes, [])
    def set_blocking_processes(self, value):
        self.options.set_value(config.program_key_blocking_processes, value)
    def add_blocking_processes(self, value):
        if isinstance(value, str):
            self.set_blocking_processes(self.get_blocking_processes() + [value])
        elif isinstance(value, list):
            self.set_blocking_processes(self.get_blocking_processes() + value)

    # Creation flags
    def get_creationflags(self):
        return self.options.get_value(config.program_key_creationflags, 0)
    def set_creationflags(self, value):
        self.options.set_value(config.program_key_creationflags, value)

    # Stdout
    def get_stdout(self):
        return self.options.get_value(config.program_key_stdout)
    def set_stdout(self, value):
        self.options.set_value(config.program_key_stdout, value)

    # Stderr
    def get_stderr(self):
        return self.options.get_value(config.program_key_stderr)
    def set_stderr(self, value):
        self.options.set_value(config.program_key_stderr, value)

    # Include stderr in stdout
    def include_stderr(self):
        return self.options.get_value(config.program_key_include_stderr, False)
    def set_include_stderr(self, value):
        self.options.set_value(config.program_key_include_stderr, value)
