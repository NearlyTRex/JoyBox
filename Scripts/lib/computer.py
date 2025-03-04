# Imports
import os, os.path
import sys
import ntpath

# Local imports
import config
import system
import environment
import jsondata
import command
import programs
import sandbox
import archive
import display
import install

# Program
class Program(jsondata.JsonData):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # Executable
    def set_exe(self, value):
        self.set_value(config.program_key_exe, value)
    def get_exe(self, token_map = None):
        return self.get_value(config.program_key_exe)
        if path and token_map:
            return sandbox.ResolvePath(path, token_map)
        return path

    # Current working directory
    def set_cwd(self, value):
        self.set_value(config.program_key_cwd, value)
    def get_cwd(self, token_map = None):
        path = self.get_value(config.program_key_cwd)
        if path and token_map:
            return sandbox.ResolvePath(path, token_map)
        return path

    # Environment variables
    def set_env(self, value):
        self.set_value(config.program_key_env, value)
    def get_env(self):
        return self.get_value(config.program_key_env)

    # Arguments
    def set_args(self, value):
        self.set_value(config.program_key_args, value)
    def get_args(self):
        return self.get_value(config.program_key_args)

    # Windows version
    def set_winver(self, value):
        self.set_value(config.program_key_winver, value)
    def get_winver(self):
        return self.get_value(config.program_key_winver)

    # Tricks
    def set_tricks(self, value):
        self.set_value(config.program_key_tricks, value)
    def get_tricks(self):
        return self.get_value(config.program_key_tricks)

    # Overrides
    def set_overrides(self, value):
        self.set_value(config.program_key_overrides, value)
    def get_overrides(self):
        return self.get_value(config.program_key_overrides)

    # Desktop resolution
    def set_desktop(self, value):
        self.set_value(config.program_key_desktop, value)
    def get_desktop(self):
        return self.get_value(config.program_key_desktop)

    # Installer type
    def set_installer_type(self, value):
        self.set_value(config.program_key_installer_type, value)
    def get_installer_type(self):
        return self.get_value(config.program_key_installer_type)

    # Serial number/key
    def set_serial(self, value):
        self.set_value(config.program_key_serial, value)
    def get_serial(self):
        return self.get_value(config.program_key_serial)

    # Is shell program
    def set_is_shell(self, value):
        self.set_value(config.program_key_is_shell, value)
    def is_shell(self):
        return self.get_value(config.program_key_is_shell, False)

    # Is 32-bit program
    def set_is_32_bit(self, value):
        self.set_value(config.program_key_is_32_bit, value)
    def is_32_bit(self):
        return self.get_value(config.program_key_is_32_bit, False)

    # Is dos program
    def set_is_dos(self, value):
        self.set_value(config.program_key_is_dos, value)
    def is_dos(self):
        return self.get_value(config.program_key_is_dos, False)

    # Is windows 3.1 program
    def set_is_win31(self, value):
        self.set_value(config.program_key_is_win31, value)
    def is_win31(self):
        return self.get_value(config.program_key_is_win31, False)

    # Is scumm program
    def set_is_scumm(self, value):
        self.set_value(config.program_key_is_scumm, value)
    def is_scumm(self):
        return self.get_value(config.program_key_is_scumm, False)

    # Run program
    def run(
        self,
        options,
        token_map,
        base_dir = None,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get program info
        program_exe = sandbox.ResolvePath(self.get_exe(), token_map)
        program_cwd = sandbox.ResolvePath(self.get_cwd(), token_map)
        program_args = self.get_args()
        program_is_dos = self.is_dos()
        program_is_win31 = self.is_win31()
        program_is_scumm = self.is_scumm()
        program_is_windows = program_exe and not program_is_dos and not program_is_win31 and not program_is_scumm
        program_path = system.JoinPaths(program_cwd, program_exe)
        if base_dir:
            program_path = system.JoinPaths(base_dir, program_cwd, program_exe)
        program_drive = system.GetFilenameDrive(program_path)
        program_dir = system.GetFilenameDirectory(program_path)
        program_file = system.GetFilenameFile(program_path)
        program_offset = system.GetFilenameDriveOffset(program_dir)
        program_options = options.copy()

        ##########################
        # DOS program
        ##########################
        if program_is_dos:

            # Update program options
            program_options.set_blocking_processes([programs.GetEmulatorProgram("DosBoxX")])

            # Get program command
            program_cmd = command.GetDosLaunchCommand(
                options = program_options,
                start_program = program_file,
                start_args = program_args,
                start_letter = program_drive,
                start_offset = program_offset,
                fullscreen = fullscreen)

        ##########################
        # Win31 programs
        ##########################
        elif program_is_win31:

            # Update program options
            program_options.set_blocking_processes([programs.GetEmulatorProgram("DosBoxX")])

            # Get program command
            program_cmd = command.GetWin31LaunchCommand(
                options = program_options,
                start_program = program_file,
                start_letter = program_drive,
                start_offset = program_offset,
                fullscreen = fullscreen)

        ##########################
        # Scumm programs
        ##########################
        elif program_is_scumm:

            # Get program command
            program_cmd = command.GetScummLaunchCommand(
                options = program_options,
                fullscreen = fullscreen)

        ##########################
        # Windows program
        ##########################
        elif program_is_windows:

            # Update program options
            program_options.set_force_prefix(True)
            program_options.set_is_prefix_mapped_cwd(True)
            program_options.set_cwd(os.path.expanduser("~"))
            program_options.add_blocking_processes([program_path])

            # Get program command
            program_cmd = [program_path] + program_args

        # Launch game
        success = command.RunCaptureCommand(
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
        success = display.RestoreDefaultScreenResolution(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Should be successful
        return True

# Program step
class ProgramStep(jsondata.JsonData):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # From
    def set_from(self, value):
        self.set_value(config.program_step_key_from, value)
    def get_from(self):
        return self.get_value(config.program_step_key_from, "")

    # To
    def set_to(self, value):
        self.set_value(config.program_step_key_to, value)
    def get_to(self):
        return self.get_value(config.program_step_key_to, "")

    # Dir
    def set_dir(self, value):
        self.set_value(config.program_step_key_dir, value)
    def get_dir(self):
        return self.get_value(config.program_step_key_dir, "")

    # Type
    def set_type(self, value):
        self.set_value(config.program_step_key_type, value)
    def get_type(self):
        return self.get_value(config.program_step_key_type)

    # Skip existing
    def set_skip_existing(self, value):
        self.set_value(config.program_step_key_skip_existing, value)
    def skip_existing(self):
        return self.get_value(config.program_step_key_skip_existing, False)

    # Skip identical
    def set_skip_identical(self, value):
        self.set_value(config.program_step_key_skip_identical, value)
    def skip_identical(self):
        return self.get_value(config.program_step_key_skip_identical, False)

    # Run program step
    def run(
        self,
        token_map,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get program step info
        program_step_from = sandbox.ResolvePath(self.get_from(), token_map)
        program_step_to = sandbox.ResolvePath(self.get_to(), token_map)
        program_step_dir = sandbox.ResolvePath(self.get_dir(), token_map)
        program_step_type = self.get_type()
        program_skip_existing = self.skip_existing()
        program_skip_identical = self.skip_identical()

        # Copy step
        if program_step_type == "copy":
            return system.SmartCopy(
                src = program_step_from,
                dest = program_step_to,
                skip_existing = program_skip_existing,
                skip_identical = program_skip_identical,
                case_sensitive_paths = False,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Move step
        elif program_step_type == "move":
            return system.SmartMove(
                src = program_step_from,
                dest = program_step_to,
                skip_existing = program_skip_existing,
                skip_identical = program_skip_identical,
                case_sensitive_paths = False,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Extract step
        elif program_step_type == "extract":
            return archive.ExtractArchive(
                archive_file = program_step_from,
                extract_dir = program_step_to,
                skip_existing = program_skip_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Lowercase step
        elif program_step_type == "lowercase":
            return system.LowercaseAllPaths(
                src = program_step_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Should be successful
        return True

# Install computer game
def InstallComputerGame(
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

    # Get setup directory
    game_setup_dir = environment.GetCacheGamingSetupDir(game_category, game_subcategory, game_name)
    success = system.MakeDirectory(
        src = game_setup_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get setup options
    game_setup_options = command.CreateCommandOptions()

    # Create prefix
    success = game_setup_options.create_prefix(
        is_wine_prefix = environment.IsWinePlatform(),
        is_sandboxie_prefix = environment.IsSandboxiePlatform(),
        prefix_name = config.PrefixType.SETUP,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Copy game files
    success = system.CopyContents(
        src = system.GetFilenameDirectory(source_file),
        dest = game_setup_dir,
        show_progress = True,
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get game disc files
    game_disc_files = system.BuildFileListByExtensions(game_setup_dir, extensions = [".chd"])

    # Build token map
    game_token_map = sandbox.BuildTokenMap(
        store_install_dir = game_info.get_main_store_install_dir(),
        setup_base_dir = game_setup_dir,
        hdd_base_dir = game_setup_options.get_prefix_c_drive_real(),
        disc_base_dir = game_setup_dir,
        disc_files = game_disc_files,
        use_drive_letters = game_keep_discs)

    # Make dos drives
    system.MakeDirectory(
        src = game_setup_options.get_prefix_dos_c_drive(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        src = game_setup_options.get_prefix_dos_d_drive(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Make scumm dir
    system.MakeDirectory(
        src = game_setup_options.get_prefix_scumm_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Process discs
    for game_disc_file in game_disc_files:

        # Mount disc
        success = sandbox.MountDiscImage(
            src = game_disc_file,
            mount_dir = system.JoinPaths(game_setup_dir, system.GetFilenameBasename(game_disc_file)),
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Keep copy of disc
        if game_keep_discs:
            success = system.CopyFileOrDirectory(
                src = game_disc_file,
                dest = game_setup_options.get_prefix_dos_d_drive(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # Run pre-install steps
    for setup_step in game_info.get_store_setup_preinstall_steps():
        setup_step.run(
            token_map = game_token_map,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Run setup programs
    for setup_program in setup_programs:
        setup_program.run(
            options = game_setup_options,
            token_map = game_token_map,
            base_dir = game_setup_options.get_prefix_c_drive_real(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Run post-install steps
    for setup_step in game_info.get_store_setup_postinstall_steps():
        setup_step.run(
            token_map = game_token_map,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Copy public files
    prefix_public_profile_path = sandbox.GetPublicProfilePath(game_setup_options)
    if os.path.exists(prefix_public_profile_path):
        system.MakeDirectory(
            src = system.JoinPaths(game_setup_options.get_prefix_c_drive_real(), "Public"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        system.CopyContents(
            src = prefix_public_profile_path,
            dest = system.JoinPaths(game_setup_options.get_prefix_c_drive_real(), "Public"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Create install image
    success = install.PackInstallImage(
        input_dir = game_setup_options.get_prefix_c_drive_real(),
        output_image = output_image,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Unmount discs
    for game_disc_file in game_disc_files:
        success = sandbox.UnmountDiscImage(
            src = game_disc_file,
            mount_dir = system.JoinPaths(game_setup_dir, system.GetFilenameBasename(game_disc_file)),
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Cleanup
    system.RemoveDirectory(
        src = game_setup_options.get_prefix_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not keep_setup_files:
        system.RemoveDirectory(
            src = game_setup_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Should be successful
    return True

# Launch computer game
def LaunchComputerGame(
    game_info,
    capture_type = None,
    capture_file = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get launch options
    launch_options = command.CreateCommandOptions()

    # Get mount links
    mount_links = []
    for obj in system.GetDirectoryContents(game_info.get_local_cache_dir()):
        mount_links.append({
            "from": system.JoinPaths(game_info.get_local_cache_dir(), obj),
            "to": obj
        })

    # Create game prefix
    def CreateGamePrefix():
        nonlocal launch_options
        return launch_options.create_prefix(
            is_wine_prefix = environment.IsLinuxPlatform(),
            is_sandboxie_prefix = environment.IsWindowsPlatform(),
            prefix_name = config.PrefixType.GAME,
            prefix_dir = game_info.get_save_dir(),
            general_prefix_dir = game_info.get_general_save_dir(),
            linked_prefix = True,
            other_links = mount_links,
            clean_existing = False,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    gui.DisplayLoadingWindow(
        title_text = "Creating game prefix",
        message_text = "Creating game prefix\n%s\n%s" % (game_info.get_name(), game_info.get_platform()),
        failure_text = "Unable to create game prefix",
        image_file = game_info.get_boxfront_asset(),
        run_func = CreateGamePrefix)

    # Build token map
    launch_token_map = sandbox.BuildTokenMap(
        hdd_base_dir = launch_options.get_prefix_c_drive_real())

    # Get base directory
    launch_base_dir = None
    if game_info.does_store_have_dos_programs():
        launch_base_dir = launch_options.get_prefix_dos_c_drive()
    elif game_info.does_store_have_win31_programs():
        launch_base_dir = launch_options.get_prefix_dos_c_drive()
    else:
        launch_base_dir = launch_options.get_prefix_c_drive_real()
    if not launch_base_dir:
        return False

    # Get selected program
    selected_program = game_info.select_store_launch_program(launch_base_dir)

    # Should be successful
    return True
