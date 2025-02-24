# Imports
import os, os.path
import sys
import ntpath

# Local imports
import config
import environment
import system
import command
import sandbox
import archive
import programs
import chd
import install
import gameinfo
import emulators

# Inno Setup parameters
inno_setup_silent_params = ["/SP-"]
inno_setup_normal_params = [
    "/NOCANCEL",
    "/NORESTART",
    "/NOCLOSEAPPLICATIONS",
    "/NOFORCECLOSEAPPLICATIONS",
    "/NORESTARTAPPLICATIONS",
    "/NOICONS"
]

# Get installer type
def GetInstallerType(installer_file):
    with open(installer_file, "r", encoding="utf8", errors="ignore") as file:
        while True:
            file_contents = file.read(2048)
            if not file_contents:
                break
            if "Inno Setup" in file_contents:
                return config.InstallerType.INNO
            if "Nullsoft.NSIS.exehead" in file_contents:
                return config.InstallerType.NSIS
            if "InstallShieldSetup" in file_contents:
                return config.InstallerType.INS
            if "7-Zip" in file_contents:
                return config.InstallerType.SEVENZIP
            if "WinRAR SFX" in file_contents:
                return config.InstallerType.WINRAR
    return config.InstallerType.UNKNOWN

# Get installer setup command
def GetInstallerSetupCommand(
    installer_file,
    installer_type,
    install_dir = None,
    silent_install = True):

    # Create installer command
    installer_cmd = [installer_file]
    if installer_type == config.InstallerType.SEVENZIP:
        if silent_install:
            installer_cmd += ["-y"]
        if install_dir:
            installer_cmd += ["-o%s" % install_dir]
    elif installer_type == config.InstallerType.WINRAR:
        if silent_install:
            installer_cmd += ["-s2"]
        if install_dir:
            installer_cmd += ["-d%s" % install_dir]
    return installer_cmd

# Run setup programs
def RunSetupPrograms(
    setup_programs,
    setup_base_dir,
    setup_discs,
    token_map,
    options,
    keep_discs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make dos drives
    system.MakeDirectory(
        src = options.get_prefix_dos_c_drive(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        src = options.get_prefix_dos_d_drive(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Make scumm dir
    system.MakeDirectory(
        src = options.get_prefix_scumm_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Keep discs
    if keep_discs:
        for setup_disc in setup_discs:
            system.CopyFileOrDirectory(
                src = setup_disc,
                dest = options.get_prefix_dos_d_drive(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Filter installers
    for setup_program in setup_programs:
        setup_program_exe = sandbox.ResolvePath(setup_program.get_exe(), token_map)
        setup_program_cwd = sandbox.ResolvePath(setup_program.get_cwd(), token_map)
        setup_program_args = setup_program.get_args()
        setup_program_type = setup_program.get_installer_type()
        setup_program_is_dos = setup_program.is_dos()
        setup_program_is_win31 = setup_program.is_win31()
        setup_program_is_scumm = setup_program.is_scumm()
        setup_program_is_windows = (
            setup_program_exe and
            not setup_program_is_dos and
            not setup_program_is_win31 and
            not setup_program_is_scumm)

        ##########################
        # DOS installer
        ##########################
        if setup_program_is_dos:

            # Get dos emulator
            dos_emulator = programs.GetEmulatorProgram("DosBoxX")

            # Get dos program
            dos_program = system.JoinPaths(setup_program_cwd, setup_program_exe)

            # Get setup command
            program_drive = system.GetFilenameDrive(dos_program)
            program_dir = system.GetFilenameDirectory(dos_program)
            program_file = system.GetFilenameFile(dos_program)
            program_offset = system.GetFilenameDriveOffset(program_dir)

            # Get setup command
            program_setup_cmd = emulators.GetComputerDosLaunchCommand(
                options = options,
                start_program = program_file,
                start_args = setup_program_args,
                start_letter = program_drive,
                start_offset = program_offset)

            # Get setup options
            program_setup_options = options.copy()
            program_setup_options.set_is_wine_prefix(sandbox.ShouldBeRunViaWine(dos_emulator))
            program_setup_options.set_is_sandboxie_prefix(sandbox.ShouldBeRunViaSandboxie(dos_emulator))
            program_setup_options.set_blocking_processes([dos_emulator])

            # Run program
            command.RunBlockingCommand(
                cmd = program_setup_cmd,
                options = program_setup_options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        ##########################
        # Windows installer
        ##########################
        elif setup_program_is_windows:

            # Get windows program
            windows_program = system.JoinPaths(setup_base_dir, setup_program_cwd, setup_program_exe)

            # Get installer type
            if not setup_program_type:
                setup_program_type = GetInstallerType(windows_program)

            # Get install name
            install_name = gameinfo.DeriveRegularNameFromGameName(system.GetFilenameBasename(windows_program))

            # Get setup command
            program_setup_cmd = GetInstallerSetupCommand(
                installer_file = windows_program,
                installer_type = setup_program_type,
                install_dir = ntpath.join(options.get_prefix_c_drive_virtual(), install_name))

            # Get blocking processes
            blocking_processes = sandbox.GetBlockingProcesses(
                options = options,
                initial_processes = [windows_program])

            # Get setup options
            program_setup_options = options.copy()
            program_setup_options.set_cwd(os.path.expanduser("~"))
            program_setup_options.set_is_prefix_mapped_cwd(True)
            program_setup_options.set_blocking_processes(blocking_processes)

            # Run program
            command.RunBlockingCommand(
                cmd = program_setup_cmd,
                options = program_setup_options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

# Run setup steps
def RunSetupSteps(
    setup_steps,
    token_map,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Filter steps
    for setup_step in setup_steps:
        setup_step_from = sandbox.ResolvePath(setup_step.get_from(), token_map)
        setup_step_to = sandbox.ResolvePath(setup_step.get_to(), token_map)
        setup_step_dir = sandbox.ResolvePath(setup_step.get_dir(), token_map)
        setup_step_type = setup_step.get_type()
        setup_skip_existing = setup_step.skip_existing()
        setup_skip_identical = setup_step.skip_identical()

        # Copy step
        if setup_step_type == "copy":
            system.SmartCopy(
                src = setup_step_from,
                dest = setup_step_to,
                skip_existing = setup_skip_existing,
                skip_identical = setup_skip_identical,
                case_sensitive_paths = False,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Move step
        elif setup_step_type == "move":
            system.SmartMove(
                src = setup_step_from,
                dest = setup_step_to,
                skip_existing = setup_skip_existing,
                skip_identical = setup_skip_identical,
                case_sensitive_paths = False,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Extract step
        elif setup_step_type == "extract":
            archive.ExtractArchive(
                archive_file = setup_step_from,
                extract_dir = setup_step_to,
                skip_existing = setup_skip_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Lowercase step
        elif setup_step_type == "lowercase":
            system.LowercaseAllPaths(
                src = setup_step_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

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
        use_drive_letters = game_info.does_store_setup_need_to_keep_discs())

    # Mount discs
    for game_disc_file in game_disc_files:
        success = sandbox.MountDiscImage(
            src = game_disc_file,
            mount_dir = system.JoinPaths(game_setup_dir, system.GetFilenameBasename(game_disc_file)),
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Run pre-install steps
    RunSetupSteps(
        setup_steps = game_info.get_store_setup_preinstall_steps(),
        token_map = game_token_map,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Run setup programs
    RunSetupPrograms(
        setup_programs = game_info.get_store_setup_install_programs(),
        setup_base_dir = game_setup_options.get_prefix_c_drive_real(),
        setup_discs = game_disc_files,
        token_map = game_token_map,
        options = game_setup_options,
        keep_discs = game_info.does_store_setup_need_to_keep_discs(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Run post-install steps
    RunSetupSteps(
        setup_steps = game_info.get_store_setup_postinstall_steps(),
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

    # Done installing
    return True
