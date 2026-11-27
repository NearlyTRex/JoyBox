# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import sandboxprefix
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import jsondata
from joybox import paths
from joybox import command
from joybox import capture
from joybox import commandbase
from joybox import programs
from joybox import prefixlayout
from joybox import sandboxdrives
from joybox import archive
from joybox import display
from joybox import install
from joybox import gui
from joybox import logger
from joybox import platform_info

# The DOSBox-X command starting a DOS or Win31 program, which blocks on DOSBox-X
def _build_dosbox_command(program_options, program_is_dos, program_file, program_args, program_drive, program_offset, fullscreen):
    program_options.set_blocking_processes([programs.get_emulator_program("DosBoxX")])
    get_launch_command = command.get_dos_launch_command if program_is_dos else command.get_win31_launch_command
    return get_launch_command(
        options = program_options,
        start_program = program_file,
        start_args = program_args,
        start_letter = program_drive,
        start_offset = program_offset,
        fullscreen = fullscreen)

# Run a Windows program through the prefix from its mapped working directory, blocking on the program
def _set_windows_program_options(program_options, program_path):
    program_options.set_force_prefix(True)
    program_options.set_is_prefix_mapped_cwd(True)
    program_options.set_cwd(os.path.expanduser("~"))
    program_options.add_blocking_processes([program_path])

# Extract a step's archive, or copy or move its files to a case-insensitive destination
def _run_file_step(step_type, src, dest, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):
    if step_type == "extract":
        return archive.extract_archive(
            archive_file = src,
            extract_dir = dest,
            skip_existing = skip_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    transfer = filebulk.smart_copy if step_type == "copy" else filebulk.smart_move
    return transfer(
        src = src,
        dest = dest,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        case_sensitive_paths = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# A launchable or setup program from a computer game's JSON: executable, working directory, Wine settings
# and whether it runs natively or under DOSBox-X or ScummVM
class Program(jsondata.JsonData):


    # Executable
    def set_exe(self, value):
        self.set_value(config.PROGRAM_KEY_EXE, value)
    # Executable path, with prefix tokens resolved when a token map is given; None when unset
    def get_exe(self, token_map = None):
        path = self.get_value(config.PROGRAM_KEY_EXE)
        if path and token_map:
            return prefixlayout.resolve_path(path, token_map)
        return path

    # Current working directory
    def set_cwd(self, value):
        self.set_value(config.PROGRAM_KEY_CWD, value)
    # Working directory, with prefix tokens resolved when a token map is given; None when unset
    def get_cwd(self, token_map = None):
        path = self.get_value(config.PROGRAM_KEY_CWD)
        if path and token_map:
            return prefixlayout.resolve_path(path, token_map)
        return path

    # Environment variables
    def set_env(self, value):
        self.set_value(config.PROGRAM_KEY_ENV, value)
    # Environment variables to run it with; None when unset
    def get_env(self):
        return self.get_value(config.PROGRAM_KEY_ENV)

    # Arguments
    def set_args(self, value):
        self.set_value(config.PROGRAM_KEY_ARGS, value)
    # Arguments passed to the executable; empty by default
    def get_args(self):
        return self.get_value(config.PROGRAM_KEY_ARGS, [])

    # Windows version
    def set_winver(self, value):
        self.set_value(config.PROGRAM_KEY_WINVER, value)
    # Windows version the Wine prefix should report; None when unset
    def get_winver(self):
        return self.get_value(config.PROGRAM_KEY_WINVER)

    # Winetricks verbs the program needs
    def set_tricks(self, value):
        self.set_value(config.PROGRAM_KEY_TRICKS, value)
    # Winetricks verbs the program needs; empty by default
    def get_tricks(self):
        return self.get_value(config.PROGRAM_KEY_TRICKS, [])

    # Wine DLL overrides the program needs
    def set_overrides(self, value):
        self.set_value(config.PROGRAM_KEY_OVERRIDES, value)
    # Wine DLL overrides the program needs; empty by default
    def get_overrides(self):
        return self.get_value(config.PROGRAM_KEY_OVERRIDES, [])

    # Desktop resolution
    def set_desktop(self, value):
        self.set_value(config.PROGRAM_KEY_DESKTOP, value)
    # Virtual desktop resolution to run in; None when unset
    def get_desktop(self):
        return self.get_value(config.PROGRAM_KEY_DESKTOP)

    # Kind of Windows installer this program is, such as Inno or NSIS
    def set_installer_type(self, value):
        self.set_value(config.PROGRAM_KEY_INSTALLER_TYPE, value)
    # Kind of Windows installer this program is; None when unset
    def get_installer_type(self):
        return self.get_value(config.PROGRAM_KEY_INSTALLER_TYPE)

    # Serial number/key
    def set_serial(self, value):
        self.set_value(config.PROGRAM_KEY_SERIAL, value)
    # Product key to enter during install; None when unset
    def get_serial(self):
        return self.get_value(config.PROGRAM_KEY_SERIAL)

    # Is shell program
    def set_is_shell(self, value):
        self.set_value(config.PROGRAM_KEY_IS_SHELL, value)
    # Whether it runs through the shell; False by default
    def is_shell(self):
        return self.get_value(config.PROGRAM_KEY_IS_SHELL, False)

    # Is daemon program
    def set_is_daemon(self, value):
        self.set_value(config.PROGRAM_KEY_IS_DAEMON, value)
    # Whether it is left running in the background; False by default
    def is_daemon(self):
        return self.get_value(config.PROGRAM_KEY_IS_DAEMON, False)

    # Is 32-bit program
    def set_is_32_bit(self, value):
        self.set_value(config.PROGRAM_KEY_IS_32_BIT, value)
    # Whether it needs a 32-bit Wine prefix; False by default
    def is_32_bit(self):
        return self.get_value(config.PROGRAM_KEY_IS_32_BIT, False)

    # Is dos program
    def set_is_dos(self, value):
        self.set_value(config.PROGRAM_KEY_IS_DOS, value)
    # Whether it runs under DOSBox-X as a DOS program; False by default
    def is_dos(self):
        return self.get_value(config.PROGRAM_KEY_IS_DOS, False)

    # Is windows 3.1 program
    def set_is_win31(self, value):
        self.set_value(config.PROGRAM_KEY_IS_WIN31, value)
    # Whether it runs under DOSBox-X in Windows 3.1; False by default
    def is_win31(self):
        return self.get_value(config.PROGRAM_KEY_IS_WIN31, False)

    # Is scumm program
    def set_is_scumm(self, value):
        self.set_value(config.PROGRAM_KEY_IS_SCUMM, value)
    # Whether it runs as a ScummVM game; False by default
    def is_scumm(self):
        return self.get_value(config.PROGRAM_KEY_IS_SCUMM, False)

    # Opt a setup program into failing the install when it exits non-zero
    def set_check_exit_code(self, value):
        self.set_value(config.PROGRAM_KEY_CHECK_EXIT_CODE, value)
    # Whether a setup run fails on a non-zero exit instead of warning; False by default, as many
    # installers exit non-zero after installing correctly
    def should_check_exit_code(self):
        return self.get_value(config.PROGRAM_KEY_CHECK_EXIT_CODE, False)

    # Resolve the executable's full path inside the prefix and whether it is a Windows program;
    # None when the entry has no executable and no dos, win31 or scumm launch type
    def resolve_launch_path(self, options, token_map):
        program_exe = prefixlayout.resolve_path(self.get_exe() or "", token_map)
        program_cwd = prefixlayout.resolve_path(self.get_cwd() or "", token_map)
        is_emulated = self.is_dos() or self.is_win31() or self.is_scumm()
        if not is_emulated and not program_exe:
            logger.log_error("Unable to launch program, no executable and no dos, win31 or scumm launch type")
            return None
        if self.is_dos() or self.is_win31():
            return paths.join_paths(options.get_prefix_dos_c_drive(), program_cwd, program_exe), False
        if not is_emulated:
            return paths.join_paths(options.get_prefix_c_drive_real(), program_cwd, program_exe), True
        return paths.join_paths(program_cwd, program_exe), False

    # Build the launch command and options for this program, with the path of a Windows executable;
    # None when the entry names nothing to run
    def build_launch(self, options, token_map, fullscreen = False):

        # Get program info
        resolved = self.resolve_launch_path(options, token_map)
        if not resolved:
            return None
        program_path, program_is_windows = resolved
        program_args = self.get_args()
        program_is_dos = self.is_dos()
        program_is_win31 = self.is_win31()
        program_is_scumm = self.is_scumm()
        program_drive = paths.get_filename_drive(program_path)
        program_dir = paths.get_filename_directory(program_path)
        program_file = paths.get_filename_file(program_path)
        program_offset = paths.get_filename_drive_offset(program_dir)
        program_options = options.copy()

        # DOS and Win31 programs run under DOSBox-X
        if program_is_dos or program_is_win31:
            program_cmd = _build_dosbox_command(
                program_options, program_is_dos, program_file, program_args, program_drive, program_offset, fullscreen)

        # Scumm programs run under ScummVM
        elif program_is_scumm:
            program_cmd = command.get_scumm_launch_command(
                options = program_options,
                fullscreen = fullscreen)

        # Windows programs run from the prefix drive
        else:
            _set_windows_program_options(program_options, program_path)
            program_cmd = [program_path] + program_args
        return program_cmd, program_options, (program_path if program_is_windows else None)

    # Run program
    def run(
        self,
        options,
        token_map,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch
        launch = self.build_launch(options, token_map, fullscreen)
        if not launch:
            return False
        program_cmd, program_options, _ = launch

        # Launch game
        success = capture.run_capture_command(
            cmd = program_cmd,
            options = program_options,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Restore default screen resolution
        success = display.restore_default_screen_resolution(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Should be successful
        return True

    # Run as an installer; False when it cannot run or, with check_exit_code, exits non-zero.
    # Other non-zero exits and an unrestored screen resolution only warn
    def run_setup(self, options, token_map, verbose = False, pretend_run = False, exit_on_failure = False):

        # Get launch
        launch = self.build_launch(options, token_map)
        if not launch:
            return False
        program_cmd, program_options, program_path = launch
        if program_path and not pretend_run and not paths.does_path_exist(program_path, case_sensitive_paths = False):
            logger.log_error("Setup program not found: %s" % program_path, quit_program = exit_on_failure)
            return False

        # Run installer
        code = command.run_returncode_command(
            cmd = program_cmd,
            options = program_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            message = "Setup program %s exited with code %s" % (program_cmd[0], code)
            if self.should_check_exit_code():
                logger.log_error(message, quit_program = exit_on_failure)
                return False
            logger.log_warning(message)

        # Restore default screen resolution
        if not display.restore_default_screen_resolution(verbose = verbose, pretend_run = pretend_run):
            logger.log_warning("Unable to restore the default screen resolution after setup")
        return True

# Program step
class ProgramStep(jsondata.JsonData):


    # Source path of a copy, move or extract step, may hold prefix tokens
    def set_from(self, value):
        self.set_value(config.PROGRAM_STEP_KEY_FROM, value)
    # Source path of the step, unresolved; empty by default
    def get_from(self):
        return self.get_value(config.PROGRAM_STEP_KEY_FROM, "")

    # Destination path of a copy, move or extract step, may hold prefix tokens
    def set_to(self, value):
        self.set_value(config.PROGRAM_STEP_KEY_TO, value)
    # Destination path of the step, unresolved; empty by default
    def get_to(self):
        return self.get_value(config.PROGRAM_STEP_KEY_TO, "")

    # Directory a lowercase step renames within, may hold prefix tokens
    def set_dir(self, value):
        self.set_value(config.PROGRAM_STEP_KEY_DIR, value)
    # Directory of a lowercase step, unresolved; empty by default
    def get_dir(self):
        return self.get_value(config.PROGRAM_STEP_KEY_DIR, "")

    # Step kind: copy, move, extract or lowercase
    def set_type(self, value):
        self.set_value(config.PROGRAM_STEP_KEY_TYPE, value)
    # Step kind: copy, move, extract or lowercase; None when unset
    def get_type(self):
        return self.get_value(config.PROGRAM_STEP_KEY_TYPE)

    # Whether a copy, move or extract step leaves files already at the destination
    def set_skip_existing(self, value):
        self.set_value(config.PROGRAM_STEP_KEY_SKIP_EXISTING, value)
    # Whether the step leaves files already at the destination; False by default
    def skip_existing(self):
        return self.get_value(config.PROGRAM_STEP_KEY_SKIP_EXISTING, False)

    # Whether a copy or move step leaves destination files with the same content
    def set_skip_identical(self, value):
        self.set_value(config.PROGRAM_STEP_KEY_SKIP_IDENTICAL, value)
    # Whether the step leaves destination files with the same content; False by default
    def skip_identical(self):
        return self.get_value(config.PROGRAM_STEP_KEY_SKIP_IDENTICAL, False)

    # Run program step
    def run(
        self,
        token_map,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get program step info
        program_step_from = prefixlayout.resolve_path(self.get_from(), token_map)
        program_step_to = prefixlayout.resolve_path(self.get_to(), token_map)
        program_step_dir = prefixlayout.resolve_path(self.get_dir(), token_map)
        program_step_type = self.get_type()
        program_skip_existing = self.skip_existing()
        program_skip_identical = self.skip_identical()

        # Copy, move or extract step
        if program_step_type in ("copy", "move", "extract"):
            return _run_file_step(
                program_step_type, program_step_from, program_step_to, program_skip_existing, program_skip_identical,
                verbose, pretend_run, exit_on_failure)

        # Lowercase step
        if program_step_type == "lowercase":
            return fileops.lowercase_all_paths(
                src = program_step_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Should be successful
        return True

# Run copy, move, extract and lowercase setup steps in order; False at the first that fails
def run_setup_steps(setup_steps, token_map, verbose = False, pretend_run = False, exit_on_failure = False):
    for setup_step in setup_steps:
        if not setup_step.run(token_map = token_map, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
            return False
    return True

# Make the setup directory and a fresh setup prefix, and copy the game's files in;
# the prefix's command options, or None on failure
def _prepare_setup_prefix(game_setup_dir, source_file, verbose, pretend_run, exit_on_failure):

    # Make setup directory
    success = fileops.make_directory(
        src = game_setup_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return None

    # Get setup options
    game_setup_options = commandbase.create_command_options()

    # Create prefix
    success = sandboxprefix.create_prefix(
        options = game_setup_options,
        is_wine_prefix = platform_info.is_wine_platform(),
        is_sandboxie_prefix = platform_info.is_sandboxie_platform(),
        prefix_name = config.PrefixType.SETUP,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return None

    # Copy game files
    success = filebulk.copy_contents(
        src = paths.get_filename_directory(source_file),
        dest = game_setup_dir,
        show_progress = True,
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return None
    return game_setup_options

# Make the prefix's DOS C and D drives and its ScummVM folder
def _make_prefix_drive_dirs(game_setup_options, verbose, pretend_run, exit_on_failure):
    for get_drive_dir in (
        game_setup_options.get_prefix_dos_c_drive,
        game_setup_options.get_prefix_dos_d_drive,
        game_setup_options.get_prefix_scumm_dir):
        fileops.make_directory(
            src = get_drive_dir(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Where a setup disc image mounts: a folder named after it in the setup directory
def _get_disc_mount_dir(game_setup_dir, game_disc_file):
    return paths.join_paths(game_setup_dir, paths.get_filename_basename(game_disc_file))

# Mount each disc image, copying it onto the DOS D drive too when the store keeps discs; False on failure
def _mount_setup_discs(game_disc_files, game_setup_dir, game_setup_options, game_keep_discs, verbose, pretend_run, exit_on_failure):
    for game_disc_file in game_disc_files:

        # Mount disc
        success = sandboxdrives.mount_disc_image(
            src = game_disc_file,
            mount_dir = _get_disc_mount_dir(game_setup_dir, game_disc_file),
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Keep copy of disc
        if game_keep_discs:
            success = fileops.copy_file_or_directory(
                src = game_disc_file,
                dest = game_setup_options.get_prefix_dos_d_drive(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

# Unmount each disc image mounted for setup; False on failure
def _unmount_setup_discs(game_disc_files, game_setup_dir, game_setup_options, verbose, pretend_run, exit_on_failure):
    for game_disc_file in game_disc_files:
        success = sandboxdrives.unmount_disc_image(
            src = game_disc_file,
            mount_dir = _get_disc_mount_dir(game_setup_dir, game_disc_file),
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Copy what setup left in the prefix's public profile onto its C drive's Public folder
def _copy_public_profile(game_setup_options, verbose, pretend_run, exit_on_failure):
    prefix_public_profile_path = prefixlayout.get_public_profile_path(game_setup_options)
    if os.path.exists(prefix_public_profile_path):
        fileops.make_directory(
            src = paths.join_paths(game_setup_options.get_prefix_c_drive_real(), "Public"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        filebulk.copy_contents(
            src = prefix_public_profile_path,
            dest = paths.join_paths(game_setup_options.get_prefix_c_drive_real(), "Public"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Run the store's pre-install steps, setup programs and post-install steps, then copy
# the public profile files; False at the first that fails
def _run_store_setup(game_info, game_setup_options, game_token_map, verbose, pretend_run, exit_on_failure):

    # Run pre-install steps
    if not run_setup_steps(game_info.get_store_setup_preinstall_steps(), game_token_map, verbose, pretend_run, exit_on_failure):
        return False

    # Run setup programs
    for setup_program in game_info.get_store_setup_install_programs():
        success = setup_program.run_setup(
            options = game_setup_options,
            token_map = game_token_map,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Run post-install steps
    if not run_setup_steps(game_info.get_store_setup_postinstall_steps(), game_token_map, verbose, pretend_run, exit_on_failure):
        return False

    # Copy public files
    _copy_public_profile(game_setup_options, verbose, pretend_run, exit_on_failure)
    return True

# Remove the setup prefix, and the setup directory unless its files are kept
def _remove_setup_files(game_setup_options, game_setup_dir, keep_setup_files, verbose, pretend_run, exit_on_failure):
    fileops.remove_directory(
        src = game_setup_options.get_prefix_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not keep_setup_files:
        fileops.remove_directory(
            src = game_setup_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Pack the prefix's C drive into the install image, unmount the discs and clean up; False on failure
def _finish_setup(
    game_setup_options, output_image, game_disc_files, game_setup_dir, keep_setup_files,
    verbose, pretend_run, exit_on_failure):

    # Create install image
    success = install.pack_install_image(
        input_dir = game_setup_options.get_prefix_c_drive_real(),
        output_image = output_image,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Unmount discs
    if not _unmount_setup_discs(game_disc_files, game_setup_dir, game_setup_options, verbose, pretend_run, exit_on_failure):
        return False

    # Cleanup
    _remove_setup_files(game_setup_options, game_setup_dir, keep_setup_files, verbose, pretend_run, exit_on_failure)
    return True

# Tokens for setup paths: the store install dir, setup and disc folders, the prefix C drive,
# and drive letters for the discs when the store keeps them
def _build_setup_token_map(game_info, game_setup_dir, game_setup_options, game_disc_files, game_keep_discs):
    return prefixlayout.build_token_map(
        store_install_dir = game_info.get_main_store_install_dir(),
        setup_base_dir = game_setup_dir,
        hdd_base_dir = game_setup_options.get_prefix_c_drive_real(),
        disc_base_dir = game_setup_dir,
        disc_files = game_disc_files,
        use_drive_letters = game_keep_discs)

# Install a computer game in a throwaway setup prefix from its source files and discs, running its store setup steps
# and programs, then pack the prefix's C drive into the output install image
def setup_computer_game(
    game_info,
    source_file,
    output_image,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_category = game_info.get_category()
    game_subcategory = game_info.get_subcategory()
    game_keep_discs = game_info.does_store_need_to_keep_discs()

    # Get setup directory and prefix
    game_setup_dir = environment.get_cache_gaming_setup_dir(game_category, game_subcategory, game_name)
    game_setup_options = _prepare_setup_prefix(game_setup_dir, source_file, verbose, pretend_run, exit_on_failure)
    if not game_setup_options:
        return False

    # Get game disc files
    game_disc_files = paths.build_file_list_by_extensions(game_setup_dir, extensions = [".chd"])

    # Build token map
    game_token_map = _build_setup_token_map(game_info, game_setup_dir, game_setup_options, game_disc_files, game_keep_discs)

    # Make drives and mount discs
    _make_prefix_drive_dirs(game_setup_options, verbose, pretend_run, exit_on_failure)
    if not _mount_setup_discs(game_disc_files, game_setup_dir, game_setup_options, game_keep_discs, verbose, pretend_run, exit_on_failure):
        return False

    # Run the store setup, then pack and clean up
    if not _run_store_setup(game_info, game_setup_options, game_token_map, verbose, pretend_run, exit_on_failure):
        return False
    return _finish_setup(
        game_setup_options, output_image, game_disc_files, game_setup_dir, keep_setup_files,
        verbose, pretend_run, exit_on_failure)

# Link each top-level entry of the game's local cache into the prefix under its own name
def _get_cache_mount_links(game_info):
    game_mount_links = []
    for obj in paths.get_directory_contents(game_info.get_local_cache_dir()):
        game_mount_links.append({
            "from": paths.join_paths(game_info.get_local_cache_dir(), obj),
            "to": obj
        })
    return game_mount_links

# Create the game's linked prefix over its save dir behind a loading window
def _create_game_prefix(game_info, game_launch_options, game_mount_links, verbose, pretend_run, exit_on_failure):

    # Create game prefix
    def create_game_prefix():
        return sandboxprefix.create_prefix(
            options = game_launch_options,
            is_wine_prefix = platform_info.is_linux_platform(),
            is_sandboxie_prefix = platform_info.is_windows_platform(),
            prefix_name = config.PrefixType.GAME,
            prefix_dir = game_info.get_save_dir(),
            general_prefix_dir = game_info.get_general_save_dir(),
            linked_prefix = True,
            other_links = game_mount_links,
            clean_existing = False,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    gui.display_loading_window(
        title_text = "Creating game prefix",
        message_text = "Creating game prefix\n%s\n%s" % (game_info.get_name(), game_info.get_platform()),
        failure_text = "Unable to create game prefix",
        image_file = game_info.get_boxfront_asset(),
        run_func = create_game_prefix)

# The folder the store's programs launch from: the DOS C drive for DOS and Win31 programs, else the prefix C drive
def _get_game_launch_dir(game_info, game_launch_options):
    if game_info.does_store_have_dos_programs():
        return game_launch_options.get_prefix_dos_c_drive()
    if game_info.does_store_have_win31_programs():
        return game_launch_options.get_prefix_dos_c_drive()
    return game_launch_options.get_prefix_c_drive_real()

# Build the game's prefix over its save dir and cached install, then run the store launch program it selects
def launch_computer_game(
    game_info,
    capture_type = None,
    capture_file = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get launch options
    game_launch_options = commandbase.create_command_options()

    # Create game prefix with mount links
    game_mount_links = _get_cache_mount_links(game_info)
    _create_game_prefix(game_info, game_launch_options, game_mount_links, verbose, pretend_run, exit_on_failure)

    # Build token map
    game_token_map = prefixlayout.build_token_map(
        hdd_base_dir = game_launch_options.get_prefix_c_drive_real())

    # Get launch directory
    game_launch_dir = _get_game_launch_dir(game_info, game_launch_options)
    if not game_launch_dir:
        return False

    # Get selected program
    game_selected_program = game_info.select_store_launch_program(game_launch_dir)
    if not game_selected_program:
        return False

    # Run program
    return game_selected_program.run(
        options = game_launch_options,
        token_map = game_token_map,
        capture_type = capture_type,
        capture_file = capture_file,
        fullscreen = fullscreen,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
