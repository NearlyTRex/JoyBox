# Imports
import os
import os.path
import copy

# Local imports
from joybox import config
from joybox import jsondata
from joybox import paths
from joybox import settings

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
        return self.options.get_value(config.PROGRAM_KEY_CWD)
    def set_cwd(self, value):
        self.options.set_value(config.PROGRAM_KEY_CWD, value)
    def has_valid_cwd(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_CWD))

    # Environment variables
    def get_env(self):
        return self.options.get_value(config.PROGRAM_KEY_ENV, dict(os.environ))
    def set_env(self, value):
        self.options.set_value(config.PROGRAM_KEY_ENV, value)
    def get_env_var(self, key):
        return self.options.get_subvalue(config.PROGRAM_KEY_ENV, key)
    def set_env_var(self, key, value):
        if not self.options.has_key(config.PROGRAM_KEY_ENV):
            self.options.set_value(config.PROGRAM_KEY_ENV, dict(os.environ))
        self.options.set_subvalue(config.PROGRAM_KEY_ENV, key, value)

    # Arguments
    def get_args(self):
        return self.options.get_value(config.PROGRAM_KEY_ARGS, [])
    def set_args(self, value):
        self.options.set_value(config.PROGRAM_KEY_ARGS, value)

    # Windows version
    def get_winver(self):
        return self.options.get_value(config.PROGRAM_KEY_WINVER)
    def set_winver(self, value):
        self.options.set_value(config.PROGRAM_KEY_WINVER, value)

    # Tricks
    def get_tricks(self):
        tricks = []
        if isinstance(self.options.get_value(config.PROGRAM_KEY_WINVER), str):
            tricks += [self.options.get_value(config.PROGRAM_KEY_WINVER)]
        tricks += self.options.get_value(config.PROGRAM_KEY_TRICKS, [])
        return tricks
    def set_tricks(self, value):
        self.options.set_value(config.PROGRAM_KEY_TRICKS, value)

    # Overrides
    def get_overrides(self):
        return self.options.get_value(config.PROGRAM_KEY_OVERRIDES, [])
    def set_overrides(self, value):
        self.options.set_value(config.PROGRAM_KEY_OVERRIDES, value)

    # Desktop width
    def get_desktop_width(self):
        ini_default = settings.get_value("UserData.Resolution", "screen_resolution_w")
        return self.options.get_value(config.PROGRAM_KEY_DESKTOP_WIDTH) or ini_default
    def set_desktop_width(self, value):
        self.options.set_value(config.PROGRAM_KEY_DESKTOP_WIDTH, value)

    # Desktop height
    def get_desktop_height(self):
        ini_default = settings.get_value("UserData.Resolution", "screen_resolution_h")
        return self.options.get_value(config.PROGRAM_KEY_DESKTOP_HEIGHT) or ini_default
    def set_desktop_height(self, value):
        self.options.set_value(config.PROGRAM_KEY_DESKTOP_HEIGHT, value)

    # Desktop dimensions
    def get_desktop_dimensions(self):
        return "%sx%s" % (self.get_desktop_width(), self.get_desktop_height())

    # Installer type
    def get_installer_type(self):
        return self.options.get_value(config.PROGRAM_KEY_INSTALLER_TYPE)
    def set_installer_type(self, value):
        self.options.set_value(config.PROGRAM_KEY_INSTALLER_TYPE, value)

    # Serial
    def get_serial(self):
        return self.options.get_value(config.PROGRAM_KEY_SERIAL)
    def set_serial(self, value):
        self.options.set_value(config.PROGRAM_KEY_SERIAL, value)

    ###########################################################
    # Flags
    ###########################################################

    # Shell execution
    def is_shell(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_SHELL, False)
    def set_is_shell(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_SHELL, value)

    # Daemon execution
    def is_daemon(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_DAEMON, False)
    def set_is_daemon(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_DAEMON, value)

    # Suppress output
    def is_output_suppressed(self):
        return self.options.get_value(config.PROGRAM_KEY_SUPPRESS_OUTPUT, False)
    def set_suppress_output(self, value):
        self.options.set_value(config.PROGRAM_KEY_SUPPRESS_OUTPUT, value)

    # Passthrough (inherit stdin/stdout/stderr directly for TUI apps)
    def is_passthrough(self):
        return self.options.get_value(config.PROGRAM_KEY_PASSTHROUGH, False)
    def set_passthrough(self, value):
        self.options.set_value(config.PROGRAM_KEY_PASSTHROUGH, value)

    # 32-bit execution
    def is_32_bit(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_32_BIT, False)
    def set_is_32_bit(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_32_BIT, value)

    # Dos execution
    def is_dos(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_DOS, False)
    def set_is_dos(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_DOS, value)

    # Windows 3.1 execution
    def is_win31(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_WIN31, False)
    def set_is_win31(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_WIN31, value)

    # Scumm execution
    def is_scumm(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_SCUMM, False)
    def set_is_scumm(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_SCUMM, value)

    # Allow processing
    def allow_processing(self):
        return self.options.get_value(config.PROGRAM_KEY_ALLOW_PROCESSING, True)
    def set_allow_processing(self, value):
        self.options.set_value(config.PROGRAM_KEY_ALLOW_PROCESSING, value)

    # Force powershell
    def force_powershell(self):
        return self.options.get_value(config.PROGRAM_KEY_FORCE_POWERSHELL, False)
    def set_force_powershell(self, value):
        self.options.set_value(config.PROGRAM_KEY_FORCE_POWERSHELL, value)

    # Force AppImage
    def force_appimage(self):
        return self.options.get_value(config.PROGRAM_KEY_FORCE_APPIMAGE, False)
    def set_force_appimage(self, value):
        self.options.set_value(config.PROGRAM_KEY_FORCE_APPIMAGE, value)

    # Use virtual desktop
    def use_virtual_desktop(self):
        return self.options.get_value(config.PROGRAM_KEY_USE_VIRTUAL_DESKTOP, False)
    def set_use_virtual_desktop(self, value):
        self.options.set_value(config.PROGRAM_KEY_USE_VIRTUAL_DESKTOP, value)

    ###########################################################
    # Prefix
    ###########################################################

    # Force prefix
    def force_prefix(self):
        return self.options.get_value(config.PROGRAM_KEY_FORCE_PREFIX, False)
    def set_force_prefix(self, value):
        self.options.set_value(config.PROGRAM_KEY_FORCE_PREFIX, value)

    # Wine prefix
    def is_wine_prefix(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_WINE_PREFIX, False)
    def set_is_wine_prefix(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_WINE_PREFIX, value)

    # Sandboxie prefix
    def is_sandboxie_prefix(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_SANDBOXIE_PREFIX, False)
    def set_is_sandboxie_prefix(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_SANDBOXIE_PREFIX, value)

    # General prefix
    def is_prefix(self):
        return self.is_wine_prefix() or self.is_sandboxie_prefix()

    # Prefix mapped current working directory
    def is_prefix_mapped_cwd(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_PREFIX_MAPPED_CWD, False)
    def set_is_prefix_mapped_cwd(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_PREFIX_MAPPED_CWD, value)

    # Prefix dir
    def get_prefix_dir(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_DIR)
    def set_prefix_dir(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_DIR, value)
    def has_valid_prefix_dir(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_PREFIX_DIR))
    def has_existing_prefix_dir(self):
        return paths.does_path_exist(self.options.get_value(config.PROGRAM_KEY_PREFIX_DIR))

    # General prefix dir
    def get_general_prefix_dir(self):
        return self.options.get_value(config.PROGRAM_KEY_GENERAL_PREFIX_DIR)
    def set_general_prefix_dir(self, value):
        self.options.set_value(config.PROGRAM_KEY_GENERAL_PREFIX_DIR, value)
    def has_valid_general_prefix_dir(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_GENERAL_PREFIX_DIR))
    def has_existing_general_prefix_dir(self):
        return paths.does_path_exist(self.options.get_value(config.PROGRAM_KEY_GENERAL_PREFIX_DIR))

    # Prefix user profile dir
    def get_prefix_user_profile_dir(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_USER_PROFILE_DIR)
    def set_prefix_user_profile_dir(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_USER_PROFILE_DIR, value)
    def has_valid_prefix_user_profile_dir(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_PREFIX_USER_PROFILE_DIR))
    def has_existing_prefix_user_profile_dir(self):
        return paths.does_path_exist(self.options.get_value(config.PROGRAM_KEY_PREFIX_USER_PROFILE_DIR))

    # Prefix user profile game data directory
    def get_prefix_user_profile_gamedata_dir(self):
        if self.has_valid_prefix_user_profile_dir():
            return paths.join_paths(self.get_prefix_user_profile_dir(), config.COMPUTER_FOLDER_GAMEDATA)
        return None

    # Prefix user profile registry directory
    def get_prefix_user_profile_registry_dir(self):
        if self.has_valid_prefix_user_profile_dir():
            return paths.join_paths(self.get_prefix_user_profile_dir(), config.COMPUTER_FOLDER_REGISTRY)
        return None

    # Prefix c drive virtual
    def get_prefix_c_drive_virtual(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_VIRTUAL)
    def set_prefix_c_drive_virtual(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_VIRTUAL, value)
    def has_valid_prefix_c_drive_virtual(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_VIRTUAL))

    # Prefix c drive real
    def get_prefix_c_drive_real(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_REAL)
    def set_prefix_c_drive_real(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_REAL, value)
    def has_valid_prefix_c_drive_real(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_REAL))
    def has_existing_prefix_c_drive_real(self):
        return paths.does_path_exist(self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_REAL))

    # Prefix dos c drive
    def get_prefix_dos_c_drive(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.COMPUTER_FOLDER_DOS, "C")
        return None
    def has_valid_prefix_dos_c_drive(self):
        return paths.is_path_valid(self.get_prefix_dos_c_drive())

    # Prefix dos d drive
    def get_prefix_dos_d_drive(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.COMPUTER_FOLDER_DOS, "D")
        return None
    def has_valid_prefix_dos_d_drive(self):
        return paths.is_path_valid(self.get_prefix_dos_d_drive())

    # Prefix scumm directory
    def get_prefix_scumm_dir(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.COMPUTER_FOLDER_SCUMM)
        return None
    def has_valid_prefix_scumm_dir(self):
        return paths.is_path_valid(self.get_prefix_scumm_dir())

    # Prefix name
    def get_prefix_name(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_NAME)
    def set_prefix_name(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_NAME, value)
    def has_prefix_name(self):
        return isinstance(self.get_prefix_name(), config.PrefixType)

    # Prefix working directory
    def get_prefix_cwd(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_CWD)
    def set_prefix_cwd(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_CWD, value)
    def has_valid_prefix_cwd(self):
        return paths.is_path_valid(self.get_prefix_cwd())
    def sync_cwd_to_prefix_cwd(self):
        if self.has_existing_prefix_c_drive_real() and self.has_valid_prefix_cwd():
            self.set_cwd(os.path.realpath(paths.join_paths(self.get_prefix_c_drive_real(), self.get_prefix_cwd())))

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

        # Imports
        from joybox import sandbox

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
        other_links = None,
        clean_existing = True,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get other links
        other_links = [] if other_links is None else other_links

        # Imports
        from joybox import sandbox
        from joybox import sandboxprefix

        # Setup prefix
        self.setup_prefix(
            is_wine_prefix = is_wine_prefix,
            is_sandboxie_prefix = is_sandboxie_prefix,
            prefix_name = prefix_name,
            prefix_dir = prefix_dir,
            general_prefix_dir = general_prefix_dir)

        # Create prefix
        if linked_prefix:
            success = sandboxprefix.create_linked_prefix(
                options = self,
                other_links = other_links,
                clean_existing = clean_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
        else:
            success = sandboxprefix.create_basic_prefix(
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
        self.set_prefix_c_drive_virtual(config.DRIVE_ROOT_WINDOWS)
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
        return self.options.get_value(config.PROGRAM_KEY_LNK_BASE_PATH)
    def set_lnk_base_path(self, value):
        self.options.set_value(config.PROGRAM_KEY_LNK_BASE_PATH, value)

    # Output paths
    def get_output_paths(self):
        return self.options.get_value(config.PROGRAM_KEY_OUTPUT_PATHS, [])
    def set_output_paths(self, value):
        self.options.set_value(config.PROGRAM_KEY_OUTPUT_PATHS, value)

    # Blocking processes
    def get_blocking_processes(self):
        return self.options.get_value(config.PROGRAM_KEY_BLOCKING_PROCESSES, [])
    def set_blocking_processes(self, value):
        self.options.set_value(config.PROGRAM_KEY_BLOCKING_PROCESSES, value)
    def add_blocking_processes(self, value):
        if isinstance(value, str):
            self.set_blocking_processes(self.get_blocking_processes() + [value])
        elif isinstance(value, list):
            self.set_blocking_processes(self.get_blocking_processes() + value)

    # Creation flags
    def get_creationflags(self):
        return self.options.get_value(config.PROGRAM_KEY_CREATIONFLAGS, 0)
    def set_creationflags(self, value):
        self.options.set_value(config.PROGRAM_KEY_CREATIONFLAGS, value)

    # Stdout
    def get_stdout(self):
        return self.options.get_value(config.PROGRAM_KEY_STDOUT)
    def set_stdout(self, value):
        self.options.set_value(config.PROGRAM_KEY_STDOUT, value)

    # Stderr
    def get_stderr(self):
        return self.options.get_value(config.PROGRAM_KEY_STDERR)
    def set_stderr(self, value):
        self.options.set_value(config.PROGRAM_KEY_STDERR, value)

    # Include stderr in stdout
    def include_stderr(self):
        return self.options.get_value(config.PROGRAM_KEY_INCLUDE_STDERR, False)
    def set_include_stderr(self, value):
        self.options.set_value(config.PROGRAM_KEY_INCLUDE_STDERR, value)

    # Stdin input (written to the process then closed; keeps secrets out of argv)
    def get_stdin_input(self):
        return self.options.get_value(config.PROGRAM_KEY_STDIN_INPUT)
    def set_stdin_input(self, value):
        self.options.set_value(config.PROGRAM_KEY_STDIN_INPUT, value)

    # Seconds a captured or output-suppressed command may run before it is stopped, or None
    def get_timeout(self):
        return self.options.get_value(config.PROGRAM_KEY_TIMEOUT)
    # Set how many seconds a command may run, None for no limit
    def set_timeout(self, value):
        self.options.set_value(config.PROGRAM_KEY_TIMEOUT, value)
