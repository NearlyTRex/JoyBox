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
import registry
import gameinfo
from emulators import computer

# Inno Setup parameters
inno_setup_silent_params = ["/SP-"]
inno_setup_normal_params = ["/NOCANCEL", "/NORESTART", "/NOCLOSEAPPLICATIONS", "/NOFORCECLOSEAPPLICATIONS", "/NORESTARTAPPLICATIONS", "/NOICONS"]

# Get installer type
def GetInstallerType(installer_file):
    with open(installer_file, "r", encoding="utf8", errors="ignore") as file:
        while True:
            file_contents = file.read(2048)
            if not file_contents:
                break
            if "Inno Setup" in file_contents:
                return config.installer_type_inno
            if "Nullsoft.NSIS.exehead" in file_contents:
                return config.installer_type_nsis
            if "InstallShieldSetup" in file_contents:
                return config.installer_type_ins
            if "7-Zip" in file_contents:
                return config.installer_type_7zip
            if "WinRAR SFX" in file_contents:
                return config.installer_type_winrar
    return config.installer_type_unknown

# Get installer setup command
def GetInstallerSetupCommand(
    installer_file,
    installer_type,
    install_dir = None,
    silent_install = True):

    # Create installer command
    installer_cmd = [installer_file]
    if installer_type == config.installer_type_inno:
        if silent_install:
            installer_cmd += inno_setup_silent_params
        installer_cmd += inno_setup_normal_params
        if install_dir:
            installer_cmd = ["/DIR=%s" % install_dir]
    elif installer_type == config.installer_type_nsis:
        if silent_install:
            installer_cmd += ["/S"]
        if install_dir:
            installer_cmd += ["/D=%s" % install_dir]
    elif installer_type == config.installer_type_7zip:
        if silent_install:
            installer_cmd += ["-y"]
        if install_dir:
            installer_cmd += ["-o%s" % install_dir]
    elif installer_type == config.installer_type_winrar:
        if silent_install:
            installer_cmd += ["-s2"]
        if install_dir:
            installer_cmd += ["-d%s" % install_dir]
    return installer_cmd

# Run windows installers
def RunWindowsInstallers(
    installer_programs,
    installer_type,
    prefix_dir,
    prefix_name,
    prefix_c_drive_virtual,
    prefix_c_drive_real,
    is_wine_prefix,
    is_sandboxie_prefix,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsList(installer_programs, "installer_programs")
    system.AssertIsValidPath(prefix_c_drive_virtual, "prefix_c_drive_virtual")
    system.AssertIsValidPath(prefix_c_drive_real, "prefix_c_drive_real")

    # Run programs
    for windows_program in installer_programs:

        # Get installer type
        game_installer_type = GetInstallerType(windows_program)
        if installer_type:
            game_installer_type = installer_type

        # Get setup command
        if game_installer_type in [config.installer_type_7zip, config.installer_type_winrar]:
            install_name = gameinfo.DeriveRegularNameFromGameName(system.GetFilenameBasename(windows_program))
            program_setup_cmd = GetInstallerSetupCommand(
                installer_file = windows_program,
                installer_type = game_installer_type,
                install_dir = ntpath.join(prefix_c_drive_virtual, install_name))
        else:
            program_setup_cmd = [windows_program]

        # Get blocking processes
        blocking_processes = sandbox.GetBlockingProcesses(
            initial_processes = [windows_program],
            is_wine_prefix = is_wine_prefix,
            is_sandboxie_prefix = is_sandboxie_prefix)

        # Run program
        command.RunBlockingCommand(
            cmd = program_setup_cmd,
            options = command.CommandOptions(
                cwd = os.path.expanduser("~"),
                prefix_dir = prefix_dir,
                prefix_name = prefix_name,
                is_wine_prefix = is_wine_prefix,
                is_sandboxie_prefix = is_sandboxie_prefix,
                is_prefix_mapped_cwd = True,
                blocking_processes = blocking_processes),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Setup dos programs
def SetupDosPrograms(
    installer_programs,
    installer_discs,
    prefix_dir,
    prefix_name,
    prefix_c_drive_virtual,
    prefix_c_drive_real,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsList(installer_programs, "installer_programs")
    system.AssertIsList(installer_discs, "installer_discs")
    system.AssertIsValidPath(prefix_c_drive_virtual, "prefix_c_drive_virtual")
    system.AssertPathExists(prefix_c_drive_real, "prefix_c_drive_real")

    # Get dos emulator
    dos_emulator = programs.GetEmulatorProgram("DosBoxX")
    system.AssertPathExists(dos_emulator, "dos_emulator")

    # Get dos drives
    dos_c_drive = os.path.join(prefix_c_drive_real, config.computer_dos_folder, "C")
    dos_d_drive = os.path.join(prefix_c_drive_real, config.computer_dos_folder, "D")
    system.MakeDirectory(dos_c_drive, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(dos_d_drive, verbose = verbose, exit_on_failure = exit_on_failure)

    # Copy installer discs
    for installer_disc in installer_discs:
        system.CopyFileOrDirectory(
            src = installer_disc,
            dest = dos_d_drive,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Run dos programs
    for dos_program in installer_programs:

        # Get setup command
        program_drive = system.GetFilenameDrive(dos_program)
        program_dir = system.GetFilenameDirectory(dos_program)
        program_file = system.GetFilenameFile(dos_program)
        program_offset = system.GetFilenameDriveOffset(program_dir)
        program_setup_cmd = computer.GetDosLaunchCommand(
            prefix_dir = prefix_dir,
            is_wine_prefix = is_wine_prefix,
            is_sandboxie_prefix = is_sandboxie_prefix,
            start_program = program_file,
            start_letter = program_drive,
            start_offset = program_offset)

        # Run program
        command.RunBlockingCommand(
            cmd = program_setup_cmd,
            options = command.CommandOptions(
                prefix_dir = prefix_dir,
                prefix_name = prefix_name,
                is_wine_prefix = sandbox.ShouldBeRunViaWine(dos_emulator),
                is_sandboxie_prefix = sandbox.ShouldBeRunViaSandboxie(dos_emulator),
                blocking_processes = [dos_emulator]),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Setup win31 programs
def SetupWin31Programs(
    installer_discs,
    prefix_dir,
    prefix_name,
    prefix_c_drive_virtual,
    prefix_c_drive_real,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsList(installer_discs, "installer_discs")
    system.AssertIsValidPath(prefix_c_drive_virtual, "prefix_c_drive_virtual")
    system.AssertPathExists(prefix_c_drive_real, "prefix_c_drive_real")

    # Get dos drives
    dos_c_drive = os.path.join(prefix_c_drive_real, config.computer_dos_folder, "C")
    dos_d_drive = os.path.join(prefix_c_drive_real, config.computer_dos_folder, "D")
    system.MakeDirectory(dos_c_drive, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(dos_d_drive, verbose = verbose, exit_on_failure = exit_on_failure)

    # Copy installer discs
    for installer_disc in installer_discs:
        system.CopyFileOrDirectory(
            src = installer_disc,
            dest = dos_d_drive,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Setup scumm programs
def SetupScummPrograms(
    prefix_dir,
    prefix_name,
    prefix_c_drive_virtual,
    prefix_c_drive_real,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsValidPath(prefix_c_drive_virtual, "prefix_c_drive_virtual")
    system.AssertPathExists(prefix_c_drive_real, "prefix_c_drive_real")

    # Get scumm emulator
    scumm_emulator = programs.GetEmulatorProgram("ScummVM")
    system.AssertPathExists(scumm_emulator, "scumm_emulator")

    # Get scumm dir
    scumm_dir = os.path.join(prefix_c_drive_real, config.computer_scumm_folder)
    system.MakeDirectory(scumm_dir, verbose = verbose, exit_on_failure = exit_on_failure)

# Run setup steps
def RunSetupSteps(
    steps,
    setup_base_dir,
    hdd_base_dir,
    disc_base_dir,
    disc_token_map,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsList(steps, "steps")
    system.AssertIsValidPath(hdd_base_dir, "hdd_base_dir")
    system.AssertIsValidPath(disc_base_dir, "disc_base_dir")
    system.AssertIsDictionary(disc_token_map, "disc_token_map")

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
                paths[path_key] = computer.ResolveJsonPath(
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
                exit_on_failure = exit_on_failure)

        # Extract step
        elif step_type == "extract":
            archive.ExtractArchive(
                archive_file = paths["from"],
                extract_dir = paths["to"],
                skip_existing = skip_existing,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Lowercase step
        elif step_type == "lowercase":
            system.LowercaseAllPaths(
                dir = paths["dir"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)

# Install computer game
def InstallComputerGame(game_info, output_image, keep_setup_files = False, verbose = False, exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_category = game_info.get_category()
    game_subcategory = game_info.get_subcategory()
    game_installer_type = game_info.get_installer_type()
    game_disc_type = game_info.get_disc_type()
    game_installer_exe_list = game_info.get_installer_exe()
    game_installer_dos_exe_list = game_info.get_installer_dos_exe()
    game_wine_setup = game_info.get_wine_setup()
    game_sandboxie_setup = game_info.get_sandboxie_setup()
    game_keep_setup_registry = game_info.get_keep_setup_registry()
    game_setup_registry_keys = game_info.get_setup_registry_keys()
    game_steps_preinstall = game_info.get_preinstall_steps()
    game_steps_postinstall = game_info.get_postinstall_steps()
    game_winver = game_info.get_winver()
    game_is_dos = game_info.is_dos()
    game_is_win31 = game_info.is_win31()
    game_is_scumm = game_info.is_scumm()

    # Get game rom dir
    game_rom_dir = environment.GetRomDir(game_category, game_subcategory, game_name)

    # Get setup directory
    game_setup_dir = environment.GetCachedSetupDir(game_category, game_subcategory, game_name)
    system.MakeDirectory(game_setup_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get game disc files
    game_disc_files = system.BuildFileListByExtensions(game_rom_dir, [".chd"])

    # Check if installation should be run via wine/sandboxie
    should_run_via_wine = environment.IsWinePlatform()
    should_run_via_sandboxie = environment.IsSandboxiePlatform()

    # Get prefix info
    prefix_name = config.prefix_name_setup
    prefix_dir = sandbox.GetPrefix(
        name = prefix_name,
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie)
    if not prefix_dir:
        return False

    # Create install prefix
    sandbox.CreateBasicPrefix(
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        prefix_winver = game_winver,
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie,
        wine_setup = game_wine_setup,
        sandboxie_setup = game_sandboxie_setup,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get prefix C drive
    prefix_c_drive_virtual = config.drive_root_windows
    prefix_c_drive_real = sandbox.GetRealDrivePath(
        prefix_dir = prefix_dir,
        drive = "c",
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie)
    if not os.path.exists(prefix_c_drive_real):
        return False

    # Build disc token map
    game_disc_token_map = computer.BuildDiscTokenMap(
        disc_files = game_disc_files,
        use_drive_letters = game_is_dos or game_is_win31)

    # Resolve installer paths
    game_installer_exe_list = computer.ResolveJsonPaths(
        paths = game_installer_exe_list,
        setup_base_dir = game_setup_dir,
        hdd_base_dir = prefix_c_drive_real,
        disc_base_dir = game_setup_dir,
        disc_token_map = game_disc_token_map)

    # Resolve dos installer paths
    game_installer_dos_exe_list = computer.ResolveJsonPaths(
        paths = game_installer_dos_exe_list,
        setup_base_dir = game_setup_dir,
        hdd_base_dir = prefix_c_drive_real,
        disc_base_dir = game_setup_dir,
        disc_token_map = game_disc_token_map)

    # Copy rom files
    system.CopyContents(
        src = game_rom_dir,
        dest = game_setup_dir,
        show_progress = True,
        skip_existing = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get game disc files again
    game_disc_files = system.BuildFileListByExtensions(game_setup_dir, [".chd"])

    # Mount discs
    for game_disc_file in game_disc_files:
        mount_dir = os.path.join(game_setup_dir, system.GetFilenameBasename(game_disc_file))
        chd.MountDiscCHD(
            chd_file = game_disc_file,
            mount_dir = mount_dir,
            disc_type = game_disc_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        sandbox.MountDirectoryToAvailableDrive(
            source_dir = mount_dir,
            prefix_dir = prefix_dir,
            is_wine_prefix = should_run_via_wine,
            is_sandboxie_prefix = should_run_via_sandboxie,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Run pre-install steps
    RunSetupSteps(
        steps = game_steps_preinstall,
        setup_base_dir = game_setup_dir,
        hdd_base_dir = prefix_c_drive_real,
        disc_base_dir = game_setup_dir,
        disc_token_map = computer.BuildDiscTokenMap(game_disc_files),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Run windows installers
    RunWindowsInstallers(
        installer_programs = game_installer_exe_list,
        installer_type = game_installer_type,
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        prefix_c_drive_virtual = prefix_c_drive_virtual,
        prefix_c_drive_real = prefix_c_drive_real,
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Setup dos programs
    if game_is_dos:
        SetupDosPrograms(
            installer_programs = game_installer_dos_exe_list,
            installer_discs = game_disc_files,
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            prefix_c_drive_virtual = prefix_c_drive_virtual,
            prefix_c_drive_real = prefix_c_drive_real,
            is_wine_prefix = should_run_via_wine,
            is_sandboxie_prefix = should_run_via_sandboxie,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Setup win31 programs
    if game_is_win31:
        SetupWin31Programs(
            installer_discs = game_disc_files,
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            prefix_c_drive_virtual = prefix_c_drive_virtual,
            prefix_c_drive_real = prefix_c_drive_real,
            is_wine_prefix = should_run_via_wine,
            is_sandboxie_prefix = should_run_via_sandboxie,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Setup scumm programs
    if game_is_scumm:
        SetupScummPrograms(
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            prefix_c_drive_virtual = prefix_c_drive_virtual,
            prefix_c_drive_real = prefix_c_drive_real,
            is_wine_prefix = should_run_via_wine,
            is_sandboxie_prefix = should_run_via_sandboxie,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Run post-install steps
    RunSetupSteps(
        steps = game_steps_postinstall,
        setup_base_dir = game_setup_dir,
        hdd_base_dir = prefix_c_drive_real,
        disc_base_dir = game_setup_dir,
        disc_token_map = computer.BuildDiscTokenMap(game_disc_files),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Copy public files
    prefix_public_profile_path = sandbox.GetPublicProfilePath(
        prefix_dir = prefix_dir,
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie)
    if os.path.exists(prefix_public_profile_path):
        prefix_public_profile_path_copy = os.path.join(prefix_c_drive_real, "Public")
        system.MakeDirectory(
            dir = prefix_public_profile_path_copy,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        system.CopyContents(
            src = prefix_public_profile_path,
            dest = prefix_public_profile_path_copy,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Backup registry
    if game_keep_setup_registry:
        prefix_registry_dir = os.path.join(prefix_c_drive_real, config.computer_registry_folder)
        prefix_registry_path = os.path.join(prefix_registry_dir, config.registry_filename_setup)
        system.MakeDirectory(
            dir = prefix_registry_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        registry.BackupUserRegistry(
            registry_file = prefix_registry_path,
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            export_keys = config.registry_export_keys_setup,
            ignore_keys = config.ignored_registry_keys_setup,
            keep_keys = game_setup_registry_keys,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Create install image
    success = install.PackInstallImage(
        input_dir = prefix_c_drive_real,
        output_image = output_image,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Unmount any mounted discs
    sandbox.UnmountAllMountedDrives(
        prefix_dir = prefix_dir,
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Cleanup
    system.RemoveDirectory(prefix_dir, verbose = verbose)
    if not keep_setup_files:
        system.RemoveDirectory(game_setup_dir, verbose = verbose)

    # Done installing
    return True
