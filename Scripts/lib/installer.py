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

# Setup windows programs
def SetupWindowsPrograms(
    installer_programs,
    installer_base_dir,
    installer_type,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Filter installers
    for installer_program in installer_programs:
        installer_wrapper = jsondata.JsonData(json_data = installer_program)
        installer_exe = installer_wrapper.get_value(config.program_key_exe)
        installer_cwd = installer_wrapper.get_value(config.program_key_cwd)
        installer_type = installer_wrapper.get_value(config.program_key_installer_type)
        installer_is_dos = installer_wrapper.get_value(config.program_key_is_dos, False)
        installer_is_win31 = installer_wrapper.get_value(config.program_key_is_win31, False)
        installer_is_scumm = installer_wrapper.get_value(config.program_key_is_scumm, False)
        if not installer_exe or not installer_cwd or installer_is_dos or installer_is_win31 or installer_is_scumm:
            continue

        # Get windows program
        windows_program = system.JoinPaths(installer_base_dir, installer_cwd, installer_exe)

        # Get installer type
        if not installer_type:
            installer_type = GetInstallerType(windows_program)

        # Get install name
        install_name = gameinfo.DeriveRegularNameFromGameName(system.GetFilenameBasename(windows_program))

        # Get setup command
        program_setup_cmd = GetInstallerSetupCommand(
            installer_file = windows_program,
            installer_type = installer_type,
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

# Setup dos programs
def SetupDosPrograms(
    installer_programs,
    installer_base_dir,
    installer_discs,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get dos emulator
    dos_emulator = programs.GetEmulatorProgram("DosBoxX")

    # Get dos drives
    system.MakeDirectory(
        dir = options.get_prefix_dos_c_drive(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        dir = options.get_prefix_dos_d_drive(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Copy installer discs
    for installer_disc in installer_discs:
        system.CopyFileOrDirectory(
            src = installer_disc,
            dest = options.get_prefix_dos_d_drive(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Filter installers
    for installer_program in installer_programs:
        installer_wrapper = jsondata.JsonData(json_data = installer_program)
        installer_exe = installer_wrapper.get_value(config.program_key_exe)
        installer_cwd = installer_wrapper.get_value(config.program_key_cwd)
        installer_type = installer_wrapper.get_value(config.program_key_installer_type)
        installer_is_dos = installer_wrapper.get_value(config.program_key_is_dos, False)
        if not installer_exe or not installer_cwd or not installer_is_dos:
            continue

        # Get dos program
        dos_program = system.JoinPaths(installer_base_dir, installer_cwd, installer_exe)

        # Get setup command
        program_drive = system.GetFilenameDrive(dos_program)
        program_dir = system.GetFilenameDirectory(dos_program)
        program_file = system.GetFilenameFile(dos_program)
        program_offset = system.GetFilenameDriveOffset(program_dir)

        # Get setup command
        program_setup_cmd = tools.GetComputerDosLaunchCommand(
            options = options,
            start_program = program_file,
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

# Setup win31 programs
def SetupWin31Programs(
    installer_programs,
    installer_base_dir,
    installer_discs,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get dos drives
    system.MakeDirectory(
        dir = options.get_prefix_dos_c_drive(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        dir = options.get_prefix_dos_d_drive(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Copy installer discs
    for installer_disc in installer_discs:
        system.CopyFileOrDirectory(
            src = installer_disc,
            dest = options.get_prefix_dos_d_drive(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Setup scumm programs
def SetupScummPrograms(
    installer_programs,
    installer_base_dir,
    installer_discs,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get scumm dir
    scumm_dir = system.JoinPaths(options.get_prefix_c_drive_real(), config.computer_folder_scumm)
    system.MakeDirectory(
        dir = scumm_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Run setup steps
def RunSetupSteps(
    steps,
    setup_base_dir,
    hdd_base_dir,
    disc_base_dir,
    disc_token_map,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Run steps
    for step in steps:

        # Get params
        paths = {}
        paths["from"] = step["from"] if "from" in step else ""
        paths["to"] = step["to"] if "to" in step else ""
        paths["dir"] = step["dir"] if "dir" in step else ""
        step_type = step["type"] if "type" in step else None
        skip_existing = step["skip_existing"] if "skip_existing" in step else False
        skip_identical = step["skip_identical"] if "skip_identical" in step else False

        # Resolve paths
        for path_key, path_value in paths.items():
            if len(path_value):
                paths[path_key] = tools.ResolveComputerJsonPath(
                    path = path_value,
                    setup_base_dir = setup_base_dir,
                    hdd_base_dir = hdd_base_dir,
                    disc_base_dir = disc_base_dir,
                    disc_token_map = disc_token_map)

        # Copy step
        if step_type == "copy":
            system.SmartCopy(
                src = paths["from"],
                dest = paths["to"],
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                case_sensitive_paths = False,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Move step
        elif step_type == "move":
            system.SmartMove(
                src = paths["from"],
                dest = paths["to"],
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                case_sensitive_paths = False,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Extract step
        elif step_type == "extract":
            archive.ExtractArchive(
                archive_file = paths["from"],
                extract_dir = paths["to"],
                skip_existing = skip_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Lowercase step
        elif step_type == "lowercase":
            system.LowercaseAllPaths(
                dir = paths["dir"],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

# Install computer game
def InstallComputerGame(
    game_info,
    output_image,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_category = game_info.get_category()
    game_subcategory = game_info.get_subcategory()

    # Get game base dir (TODO: this doesn't have a source type)
    game_base_dir = environment.GetLockerGamingFilesDir(game_category, game_subcategory, game_name)

    # Get game disc files (TODO: This could easily be gotten from just the game json file instead of the base dir)
    game_disc_files = system.BuildFileListByExtensions(game_base_dir, [".chd"])

    # Get setup directory
    game_setup_dir = environment.GetCacheGamingSetupDir(game_category, game_subcategory, game_name)
    system.MakeDirectory(
        dir = game_setup_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get setup options
    game_setup_options = command.CreateCommandOptions(
        is_dos = game_info.does_store_setup_have_dos_installers(),
        is_win31 = game_info.does_store_setup_have_win31_installers(),
        is_scumm = game_info.does_store_setup_have_scumm_installers(),
        is_wine_prefix = environment.IsWinePlatform(),
        is_sandboxie_prefix = environment.IsSandboxiePlatform(),
        prefix_dir = sandbox.GetPrefix(
            name = config.PrefixType.SETUP,
            is_wine_prefix = environment.IsWinePlatform(),
            is_sandboxie_prefix = environment.IsSandboxiePlatform()),
        prefix_name = config.PrefixType.SETUP,
        prefix_winver = game_info.get_winver())

    # Create setup prefix
    sandbox.CreateBasicPrefix(
        options = game_setup_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get prefix C drive
    game_setup_options.set_prefix_c_drive_virtual(config.drive_root_windows)
    game_setup_options.set_prefix_c_drive_real(sandbox.GetRealCDrivePath(game_setup_options))
    if not game_setup_options.has_existing_prefix_c_drive_real():
        return False

    # Build disc token map
    game_disc_token_map = tools.BuildComputerDiscTokenMap(
        disc_files = game_disc_files,
        use_drive_letters = game_setup_options.is_dos() or game_setup_options.is_win31())

    # Resolve installer paths
    game_setup_install = tools.ResolveComputerProgramPaths(
        paths = game_setup_install,
        setup_base_dir = game_setup_dir,
        hdd_base_dir = game_setup_options.get_prefix_c_drive_real(),
        disc_base_dir = game_setup_dir,
        disc_token_map = game_disc_token_map)

    # Copy game files
    system.CopyContents(
        src = game_base_dir,
        dest = game_setup_dir,
        show_progress = True,
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get game disc files again
    game_disc_files = system.BuildFileListByExtensions(game_setup_dir, [".chd"])

    # Mount discs
    for game_disc_file in game_disc_files:
        mount_dir = system.JoinPaths(game_setup_dir, system.GetFilenameBasename(game_disc_file))
        chd.MountDiscCHD(
            chd_file = game_disc_file,
            mount_dir = mount_dir,
            disc_type = game_disc_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        sandbox.MountDirectoryToAvailableDrive(
            src = mount_dir,
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Run pre-install steps
    RunSetupSteps(
        steps = game_info.get_store_setup_preinstall(),
        setup_base_dir = game_setup_dir,
        hdd_base_dir = game_setup_options.get_prefix_c_drive_real(),
        disc_base_dir = game_setup_dir,
        disc_token_map = tools.BuildComputerDiscTokenMap(game_disc_files),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Setup windows programs
    SetupWindowsPrograms(
        installer_programs = game_info.get_store_setup_install(),
        installer_base_dir = game_setup_options.get_prefix_c_drive_real(),
        installer_type = game_installer_type,
        options = game_setup_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Setup dos programs
    if game_setup_options.is_dos():
        SetupDosPrograms(
            installer_programs = game_info.get_store_setup_install(),
            installer_base_dir = game_setup_options.get_prefix_c_drive_real(),
            installer_discs = game_disc_files,
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup win31 programs
    if game_setup_options.is_win31():
        SetupWin31Programs(
            installer_programs = game_info.get_store_setup_install(),
            installer_base_dir = game_setup_options.get_prefix_c_drive_real(),
            installer_discs = game_disc_files,
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup scumm programs
    if game_setup_options.is_scumm():
        SetupScummPrograms(
            installer_programs = game_info.get_store_setup_install(),
            installer_base_dir = game_setup_options.get_prefix_c_drive_real(),
            installer_discs = game_disc_files,
            options = game_setup_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Run post-install steps
    RunSetupSteps(
        steps = game_info.get_store_setup_postinstall(),
        setup_base_dir = game_setup_dir,
        hdd_base_dir = game_setup_options.get_prefix_c_drive_real(),
        disc_base_dir = game_setup_dir,
        disc_token_map = tools.BuildComputerDiscTokenMap(game_disc_files),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Copy public files
    prefix_public_profile_path = sandbox.GetPublicProfilePath(game_setup_options)
    if os.path.exists(prefix_public_profile_path):
        system.MakeDirectory(
            dir = system.JoinPaths(game_setup_options.get_prefix_c_drive_real(), "Public"),
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

    # Unmount any mounted discs
    sandbox.UnmountAllMountedDrives(
        options = game_setup_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Cleanup
    system.RemoveDirectory(
        dir = game_setup_options.get_prefix_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not keep_setup_files:
        system.RemoveDirectory(
            dir = game_setup_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Done installing
    return True
