# Imports
import os
import os.path
import copy

# Local imports
from joybox import config
from joybox import jsondata
from joybox import paths
from joybox import prefixlayout
from joybox import settings

# Command options
class CommandOptions:

    # Constructor
    def __init__(self, **kwargs):
        self.options = jsondata.JsonData()
        for key, value in kwargs.items():
            self.options.set_value(key, value)

    # Deep copy, so changes to the copy's environment and lists leave this one alone
    def copy(self):
        return copy.deepcopy(self)

    ###########################################################
    # Core
    ###########################################################

    # Working directory
    def get_cwd(self):
        return self.options.get_value(config.PROGRAM_KEY_CWD)
    # Set the directory the command starts in
    def set_cwd(self, value):
        self.options.set_value(config.PROGRAM_KEY_CWD, value)
    # Whether a working directory is set to a usable path, existing or not
    def has_valid_cwd(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_CWD))

    # Environment variables
    def get_env(self):
        return self.options.get_value(config.PROGRAM_KEY_ENV, dict(os.environ))
    # Replace the whole environment the command runs with
    def set_env(self, value):
        self.options.set_value(config.PROGRAM_KEY_ENV, value)
    # One variable from the environment set on these options; None when no environment is set or it lacks the key
    def get_env_var(self, key):
        return self.options.get_subvalue(config.PROGRAM_KEY_ENV, key)
    # Set one environment variable, starting from a copy of this process's environment when none is set yet
    def set_env_var(self, key, value):
        if not self.options.has_key(config.PROGRAM_KEY_ENV):
            self.options.set_value(config.PROGRAM_KEY_ENV, dict(os.environ))
        self.options.set_subvalue(config.PROGRAM_KEY_ENV, key, value)

    # Arguments
    def get_args(self):
        return self.options.get_value(config.PROGRAM_KEY_ARGS, [])
    # Set the extra arguments stored with the program
    def set_args(self, value):
        self.options.set_value(config.PROGRAM_KEY_ARGS, value)

    # Windows version
    def get_winver(self):
        return self.options.get_value(config.PROGRAM_KEY_WINVER)
    # Set the Windows version the Wine prefix reports, as a winetricks verb such as win7
    def set_winver(self, value):
        self.options.set_value(config.PROGRAM_KEY_WINVER, value)

    # Winetricks verbs to apply to the prefix, with the Windows version verb first when one is set
    def get_tricks(self):
        tricks = []
        if isinstance(self.options.get_value(config.PROGRAM_KEY_WINVER), str):
            tricks += [self.options.get_value(config.PROGRAM_KEY_WINVER)]
        tricks += self.options.get_value(config.PROGRAM_KEY_TRICKS, [])
        return tricks
    # Set the winetricks verbs to apply, not counting the Windows version
    def set_tricks(self, value):
        self.options.set_value(config.PROGRAM_KEY_TRICKS, value)

    # Wine DLL overrides, as name=mode entries added to WINEDLLOVERRIDES; empty by default
    def get_overrides(self):
        return self.options.get_value(config.PROGRAM_KEY_OVERRIDES, [])
    # Set the Wine DLL override entries
    def set_overrides(self, value):
        self.options.set_value(config.PROGRAM_KEY_OVERRIDES, value)

    # Virtual desktop width in pixels, falling back to the screen width from the settings
    def get_desktop_width(self):
        ini_default = settings.get_value("UserData.Resolution", "screen_resolution_w")
        return self.options.get_value(config.PROGRAM_KEY_DESKTOP_WIDTH) or ini_default
    # Set the virtual desktop width in pixels
    def set_desktop_width(self, value):
        self.options.set_value(config.PROGRAM_KEY_DESKTOP_WIDTH, value)

    # Virtual desktop height in pixels, falling back to the screen height from the settings
    def get_desktop_height(self):
        ini_default = settings.get_value("UserData.Resolution", "screen_resolution_h")
        return self.options.get_value(config.PROGRAM_KEY_DESKTOP_HEIGHT) or ini_default
    # Set the virtual desktop height in pixels
    def set_desktop_height(self, value):
        self.options.set_value(config.PROGRAM_KEY_DESKTOP_HEIGHT, value)

    # Virtual desktop size as WIDTHxHEIGHT, for Wine's explorer /desktop
    def get_desktop_dimensions(self):
        return "%sx%s" % (self.get_desktop_width(), self.get_desktop_height())

    # Kind of Windows installer the command runs, such as Inno or NSIS; None when unset
    def get_installer_type(self):
        return self.options.get_value(config.PROGRAM_KEY_INSTALLER_TYPE)
    # Set the kind of Windows installer the command runs
    def set_installer_type(self, value):
        self.options.set_value(config.PROGRAM_KEY_INSTALLER_TYPE, value)

    # Product key to enter during install; None when unset
    def get_serial(self):
        return self.options.get_value(config.PROGRAM_KEY_SERIAL)
    # Set the product key to enter during install
    def set_serial(self, value):
        self.options.set_value(config.PROGRAM_KEY_SERIAL, value)

    ###########################################################
    # Flags
    ###########################################################

    # Shell execution
    def is_shell(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_SHELL, False)
    # Set whether the command runs through the shell as one string
    def set_is_shell(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_SHELL, value)

    # Daemon execution
    def is_daemon(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_DAEMON, False)
    # Set whether the command is left running in the background without post-processing
    def set_is_daemon(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_DAEMON, value)

    # Suppress output
    def is_output_suppressed(self):
        return self.options.get_value(config.PROGRAM_KEY_SUPPRESS_OUTPUT, False)
    # Set whether the command's output is discarded
    def set_suppress_output(self, value):
        self.options.set_value(config.PROGRAM_KEY_SUPPRESS_OUTPUT, value)

    # Passthrough (inherit stdin/stdout/stderr directly for TUI apps)
    def is_passthrough(self):
        return self.options.get_value(config.PROGRAM_KEY_PASSTHROUGH, False)
    # Set whether the command uses this terminal's stdin, stdout and stderr directly
    def set_passthrough(self, value):
        self.options.set_value(config.PROGRAM_KEY_PASSTHROUGH, value)

    # 32-bit execution
    def is_32_bit(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_32_BIT, False)
    # Set whether a Wine prefix is made 32-bit rather than 64-bit
    def set_is_32_bit(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_32_BIT, value)

    # Dos execution
    def is_dos(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_DOS, False)
    # Set whether the program runs under DOSBox-X as a DOS program
    def set_is_dos(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_DOS, value)

    # Windows 3.1 execution
    def is_win31(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_WIN31, False)
    # Set whether the program runs under DOSBox-X in Windows 3.1
    def set_is_win31(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_WIN31, value)

    # Scumm execution
    def is_scumm(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_SCUMM, False)
    # Set whether the program runs as a ScummVM game
    def set_is_scumm(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_SCUMM, value)

    # Whether the PowerShell, AppImage and prefix wrapping and post-run cleanup apply; True by default
    def allow_processing(self):
        return self.options.get_value(config.PROGRAM_KEY_ALLOW_PROCESSING, True)
    # Set whether the command gets wrapping and post-run cleanup
    def set_allow_processing(self, value):
        self.options.set_value(config.PROGRAM_KEY_ALLOW_PROCESSING, value)

    # Whether to wrap the command in PowerShell even when it does not name it; False by default
    def force_powershell(self):
        return self.options.get_value(config.PROGRAM_KEY_FORCE_POWERSHELL, False)
    # Set whether to wrap the command in PowerShell regardless of its program
    def set_force_powershell(self, value):
        self.options.set_value(config.PROGRAM_KEY_FORCE_POWERSHELL, value)

    # Whether to set up AppImage home folders even when the program is not an .AppImage; False by default
    def force_appimage(self):
        return self.options.get_value(config.PROGRAM_KEY_FORCE_APPIMAGE, False)
    # Set whether to apply AppImage setup regardless of its program
    def set_force_appimage(self, value):
        self.options.set_value(config.PROGRAM_KEY_FORCE_APPIMAGE, value)

    # Whether Wine runs the program inside an explorer virtual desktop; False by default
    def use_virtual_desktop(self):
        return self.options.get_value(config.PROGRAM_KEY_USE_VIRTUAL_DESKTOP, False)
    # Set whether Wine runs the program in a virtual desktop
    def set_use_virtual_desktop(self, value):
        self.options.set_value(config.PROGRAM_KEY_USE_VIRTUAL_DESKTOP, value)

    ###########################################################
    # Prefix
    ###########################################################

    # Whether to run in a Wine or Sandboxie prefix even when the program would not need one; False by default
    def force_prefix(self):
        return self.options.get_value(config.PROGRAM_KEY_FORCE_PREFIX, False)
    # Set whether to run in a prefix regardless of its program
    def set_force_prefix(self, value):
        self.options.set_value(config.PROGRAM_KEY_FORCE_PREFIX, value)

    # Whether the command runs in a Wine prefix; False by default
    def is_wine_prefix(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_WINE_PREFIX, False)
    # Set whether the command runs in a Wine prefix
    def set_is_wine_prefix(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_WINE_PREFIX, value)

    # Whether the command runs in a Sandboxie box; False by default
    def is_sandboxie_prefix(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_SANDBOXIE_PREFIX, False)
    # Set whether the command runs in a Sandboxie box
    def set_is_sandboxie_prefix(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_SANDBOXIE_PREFIX, value)

    # General prefix
    def is_prefix(self):
        return self.is_wine_prefix() or self.is_sandboxie_prefix()

    # Prefix mapped current working directory
    def is_prefix_mapped_cwd(self):
        return self.options.get_value(config.PROGRAM_KEY_IS_PREFIX_MAPPED_CWD, False)
    # Set whether the working directory is symlinked into the Wine prefix as a drive
    def set_is_prefix_mapped_cwd(self, value):
        self.options.set_value(config.PROGRAM_KEY_IS_PREFIX_MAPPED_CWD, value)

    # Directory holding the Wine prefix or Sandboxie box; None when unset
    def get_prefix_dir(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_DIR)
    # Set the directory holding the prefix
    def set_prefix_dir(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_DIR, value)
    # Whether a prefix directory is set to a usable path, existing or not
    def has_valid_prefix_dir(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_PREFIX_DIR))
    # Whether the prefix directory is set and exists on disk
    def has_existing_prefix_dir(self):
        return paths.does_path_exist(self.options.get_value(config.PROGRAM_KEY_PREFIX_DIR))

    # Shared user-folder directory linked in as the prefix's user profile; None when unset
    def get_general_prefix_dir(self):
        return self.options.get_value(config.PROGRAM_KEY_GENERAL_PREFIX_DIR)
    # Set the shared user-folder directory linked into the prefix
    def set_general_prefix_dir(self, value):
        self.options.set_value(config.PROGRAM_KEY_GENERAL_PREFIX_DIR, value)
    # Whether the shared user-folder directory is set to a usable path, existing or not
    def has_valid_general_prefix_dir(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_GENERAL_PREFIX_DIR))
    # Whether the shared user-folder directory is set and exists on disk
    def has_existing_general_prefix_dir(self):
        return paths.does_path_exist(self.options.get_value(config.PROGRAM_KEY_GENERAL_PREFIX_DIR))

    # User profile directory inside the prefix; None when unset
    def get_prefix_user_profile_dir(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_USER_PROFILE_DIR)
    # Set the user profile directory inside the prefix
    def set_prefix_user_profile_dir(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_USER_PROFILE_DIR, value)
    # Whether the prefix user profile directory is set to a usable path, existing or not
    def has_valid_prefix_user_profile_dir(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_PREFIX_USER_PROFILE_DIR))
    # Whether the prefix user profile directory is set and exists on disk
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

    # The prefix's C drive as the program sees it, such as C:\; None when unset
    def get_prefix_c_drive_virtual(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_VIRTUAL)
    # Set the prefix's C drive path as the program sees it
    def set_prefix_c_drive_virtual(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_VIRTUAL, value)
    # Whether the program-side C drive path is set to a usable path
    def has_valid_prefix_c_drive_virtual(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_VIRTUAL))

    # Host directory backing the prefix's C drive; None when unset
    def get_prefix_c_drive_real(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_REAL)
    # Set the host directory backing the prefix's C drive
    def set_prefix_c_drive_real(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_REAL, value)
    # Whether the host C drive directory is set to a usable path, existing or not
    def has_valid_prefix_c_drive_real(self):
        return paths.is_path_valid(self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_REAL))
    # Whether the host C drive directory is set and exists on disk
    def has_existing_prefix_c_drive_real(self):
        return paths.does_path_exist(self.options.get_value(config.PROGRAM_KEY_PREFIX_C_DRIVE_REAL))

    # Host folder DOSBox-X mounts as C, under the prefix's C drive; None without one
    def get_prefix_dos_c_drive(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.COMPUTER_FOLDER_DOS, "C")
        return None
    # Whether the prefix has a host C drive to hold the DOSBox-X C folder
    def has_valid_prefix_dos_c_drive(self):
        return paths.is_path_valid(self.get_prefix_dos_c_drive())

    # Host folder searched for CHD discs to mount in DOSBox-X, under the prefix's C drive; None without one
    def get_prefix_dos_d_drive(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.COMPUTER_FOLDER_DOS, "D")
        return None
    # Whether the prefix has a host C drive to hold the DOSBox-X disc folder
    def has_valid_prefix_dos_d_drive(self):
        return paths.is_path_valid(self.get_prefix_dos_d_drive())

    # Prefix scumm directory
    def get_prefix_scumm_dir(self):
        if self.has_valid_prefix_c_drive_real():
            return paths.join_paths(self.get_prefix_c_drive_real(), config.COMPUTER_FOLDER_SCUMM)
        return None
    # Whether the prefix has a host C drive to hold the ScummVM game folder
    def has_valid_prefix_scumm_dir(self):
        return paths.is_path_valid(self.get_prefix_scumm_dir())

    # Which prefix the command uses, as a PrefixType; also the Sandboxie box name
    def get_prefix_name(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_NAME)
    # Set which PrefixType the command uses
    def set_prefix_name(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_NAME, value)
    # Whether the prefix name is set to a PrefixType member
    def has_prefix_name(self):
        return isinstance(self.get_prefix_name(), config.PrefixType)

    # Prefix working directory
    def get_prefix_cwd(self):
        return self.options.get_value(config.PROGRAM_KEY_PREFIX_CWD)
    # Set the working directory relative to the prefix's C drive
    def set_prefix_cwd(self, value):
        self.options.set_value(config.PROGRAM_KEY_PREFIX_CWD, value)
    # Whether a prefix-relative working directory is set to a usable path
    def has_valid_prefix_cwd(self):
        return paths.is_path_valid(self.get_prefix_cwd())
    # Point the working directory at the prefix-relative one on the host C drive, when both exist
    def sync_cwd_to_prefix_cwd(self):
        if self.has_existing_prefix_c_drive_real() and self.has_valid_prefix_cwd():
            self.set_cwd(os.path.realpath(paths.join_paths(self.get_prefix_c_drive_real(), self.get_prefix_cwd())))

    # Whether these options name a Wine or Sandboxie prefix whose directory already exists
    def has_ready_prefix(self):
        if not self.is_prefix():
            return False
        if not self.has_prefix_name():
            return False
        if not self.has_existing_prefix_dir():
            return False
        return True

    # Mark the command as running in the named Wine or Sandboxie prefix, working out its directory
    # from the prefix layout when none is given
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
            prefix_dir = prefixlayout.get_prefix(self)
        if paths.is_path_valid(prefix_dir):
            self.set_prefix_dir(prefix_dir)

        # General prefix dir
        if paths.is_path_valid(general_prefix_dir):
            self.set_general_prefix_dir(general_prefix_dir)

    ###########################################################
    # Other
    ###########################################################

    # Link base path
    def get_lnk_base_path(self):
        return self.options.get_value(config.PROGRAM_KEY_LNK_BASE_PATH)
    # Set the directory a .lnk's drive-relative target and working directory resolve against
    def set_lnk_base_path(self, value):
        self.options.set_value(config.PROGRAM_KEY_LNK_BASE_PATH, value)

    # Paths the command writes, copied back out of the sandbox after it runs; empty by default
    def get_output_paths(self):
        return self.options.get_value(config.PROGRAM_KEY_OUTPUT_PATHS, [])
    # Set the paths copied back out of the sandbox after the command runs
    def set_output_paths(self, value):
        self.options.set_value(config.PROGRAM_KEY_OUTPUT_PATHS, value)

    # Process names to wait on after the command returns, before post-processing; empty by default
    def get_blocking_processes(self):
        return self.options.get_value(config.PROGRAM_KEY_BLOCKING_PROCESSES, [])
    # Set the process names to wait on after the command returns
    def set_blocking_processes(self, value):
        self.options.set_value(config.PROGRAM_KEY_BLOCKING_PROCESSES, value)
    # Append one process name or a list of them to those waited on
    def add_blocking_processes(self, value):
        if isinstance(value, str):
            self.set_blocking_processes(self.get_blocking_processes() + [value])
        elif isinstance(value, list):
            self.set_blocking_processes(self.get_blocking_processes() + value)

    # Creation flags
    def get_creationflags(self):
        return self.options.get_value(config.PROGRAM_KEY_CREATIONFLAGS, 0)
    # Set the Windows process creation flags passed to subprocess
    def set_creationflags(self, value):
        self.options.set_value(config.PROGRAM_KEY_CREATIONFLAGS, value)

    # Stream or file the command's stdout goes to instead of being captured; None when unset
    def get_stdout(self):
        return self.options.get_value(config.PROGRAM_KEY_STDOUT)
    # Set where the command's stdout goes
    def set_stdout(self, value):
        self.options.set_value(config.PROGRAM_KEY_STDOUT, value)

    # Stream or file the command's stderr goes to instead of being captured; None when unset
    def get_stderr(self):
        return self.options.get_value(config.PROGRAM_KEY_STDERR)
    # Set where the command's stderr goes
    def set_stderr(self, value):
        self.options.set_value(config.PROGRAM_KEY_STDERR, value)

    # Include stderr in stdout
    def include_stderr(self):
        return self.options.get_value(config.PROGRAM_KEY_INCLUDE_STDERR, False)
    # Set whether stderr is merged into the captured stdout
    def set_include_stderr(self, value):
        self.options.set_value(config.PROGRAM_KEY_INCLUDE_STDERR, value)

    # Stdin input (written to the process then closed; keeps secrets out of argv)
    def get_stdin_input(self):
        return self.options.get_value(config.PROGRAM_KEY_STDIN_INPUT)
    # Set the text written to the command's stdin before it is closed
    def set_stdin_input(self, value):
        self.options.set_value(config.PROGRAM_KEY_STDIN_INPUT, value)

    # Seconds a captured or output-suppressed command may run before it is stopped, or None
    def get_timeout(self):
        return self.options.get_value(config.PROGRAM_KEY_TIMEOUT)
    # Set how many seconds a command may run, None for no limit
    def set_timeout(self, value):
        self.options.set_value(config.PROGRAM_KEY_TIMEOUT, value)
