# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import platforms
import gameinfo
import install
import installer
import archive
import iso
import chd
import playstation
import xbox

# Transform game file
def TransformGameFile(
    game_platform,
    game_name,
    source_game_file,
    source_json_file,
    output_dir,
    keep_setup_files = False,
    verbose = False,
    exit_on_failure = False):

    # No transform needed
    if not platforms.AreTransformsRequired(game_platform):
        return (True, source_game_file)

    # Output dir doesn't exist
    if not os.path.isdir(output_dir):
        return (False, "Output directory doesn't exist")

    # Flags
    has_exe_to_install = platforms.HasTransformType(game_platform, config.transform_exe_to_install)
    has_exe_to_raw_plain = platforms.HasTransformType(game_platform, config.transform_exe_to_raw_plain)
    has_chd_to_iso = platforms.HasTransformType(game_platform, config.transform_chd_to_iso)
    has_iso_to_xiso = platforms.HasTransformType(game_platform, config.transform_iso_to_xiso)
    has_iso_to_raw_plain = platforms.HasTransformType(game_platform, config.transform_iso_to_raw_plain)
    has_iso_to_raw_ps3 = platforms.HasTransformType(game_platform, config.transform_iso_to_raw_ps3)
    has_pkg_to_raw_ps3 = platforms.HasTransformType(game_platform, config.transform_pkg_to_raw_ps3)
    has_pkg_to_raw_psv = platforms.HasTransformType(game_platform, config.transform_pkg_to_raw_psv)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return (False, tmp_dir_result)

    # Get game categories
    game_supercategory, game_category, game_subcategory = gameinfo.DeriveGameCategoriesFromPlatform(game_platform)

    # Get game file info
    iso_tmp_dir = os.path.join(tmp_dir_result, "iso")
    install_tmp_dir = os.path.join(tmp_dir_result, "install")
    raw_tmp_dir = os.path.join(tmp_dir_result, "raw")
    cached_install_dir = environment.GetInstallRomDir(game_category, game_subcategory, game_name)
    cached_install_file = os.path.join(cached_install_dir, game_name + ".install")
    source_game_file_dir = system.GetFilenameDirectory(source_game_file)
    source_game_file_basename = system.GetFilenameBasename(source_game_file)
    source_game_file_ext = system.GetFilenameExtension(source_game_file)
    tmp_iso_bin_file = os.path.join(iso_tmp_dir, source_game_file_basename + ".iso")
    tmp_iso_toc_file = os.path.join(iso_tmp_dir, source_game_file_basename + ".toc")
    tmp_install_file = os.path.join(install_tmp_dir, source_game_file_basename + ".install")
    tmp_raw_file_index = os.path.join(raw_tmp_dir, config.raw_files_index)
    transformed_game_output = ""

    # Make directories
    system.MakeDirectory(iso_tmp_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(install_tmp_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(raw_tmp_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    ######################################################
    # Phase 1: Convert to iso files
    ######################################################

    # Convert CHD to ISO
    if has_chd_to_iso:

        # Extract CHD
        chd.ExtractDiscCHD(
            chd_file = source_game_file,
            binary_file = tmp_iso_bin_file,
            toc_file = tmp_iso_toc_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set transformed output
        transformed_game_output = tmp_iso_bin_file

    ######################################################
    # Phase 2: Convert/extract iso files
    ######################################################

    # Convert ISO to XISO
    if has_chd_to_iso and has_iso_to_xiso and os.path.exists(tmp_iso_bin_file):

        # Rewrite ISO
        xbox.RewriteXboxISO(
            iso_file = tmp_iso_bin_file,
            delete_original = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set transformed output
        transformed_game_output = tmp_iso_bin_file

    # Convert ISO to PS3 raw files
    elif has_chd_to_iso and has_iso_to_raw_ps3 and os.path.exists(tmp_iso_bin_file):

        # Get dkey file
        dkey_file = os.path.join(source_game_file_dir, source_game_file_basename + ".dkey")
        if not os.path.exists(dkey_file):
            return (False, "Unable to find corresponding dkey file")

        # Extract ISO
        playstation.ExtractPS3ISO(
            iso_file = tmp_iso_bin_file,
            dkey_file = dkey_file,
            extract_dir = raw_tmp_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Extract pkg files
        for pkg_file in system.BuildFileListByExtensions(raw_tmp_dir, extensions = [".PKG"]):
            should_extract = False
            if "PS3_GAME/PKGDIR" in pkg_file:
                should_extract = True
            if "PS3_EXTRA" in pkg_file:
                should_extract = True
            if should_extract:
                pkg_dir = system.GetFilenameDirectory(pkg_file)
                pkg_name = system.GetFilenameBasename(pkg_file)
                playstation.ExtractPSNPKG(
                    pkg_file = pkg_file,
                    extract_dir = os.path.join(pkg_dir, pkg_name),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

        # Touch index file
        system.TouchFile(
            src = tmp_raw_file_index,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set transformed output
        transformed_game_output = tmp_raw_file_index

    # Convert ISO to raw files
    elif has_chd_to_iso and has_iso_to_raw_plain and os.path.exists(tmp_iso_bin_file):

        # Extract ISO
        iso.ExtractISO(
            iso_file = tmp_iso_bin_file,
            extract_dir = raw_tmp_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Touch index file
        system.TouchFile(
            src = tmp_raw_file_index,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set transformed output
        transformed_game_output = tmp_raw_file_index

    ######################################################
    # Phase 3: Extract pkg files
    ######################################################

    # Convert PS3 PKG to raw PS3 files
    if has_pkg_to_raw_ps3:

        # Copy rap files
        for obj in system.GetDirectoryContents(source_game_file_dir):
            if obj.endswith(".rap"):
                rap_file = os.path.join(source_game_file_dir, obj)
                pkg_file = os.path.join(source_game_file_dir, obj.replace(".rap", ".pkg"))
                content_id = playstation.GetPSNPKGContentID(pkg_file)
                system.CopyFileOrDirectory(
                    src = rap_file,
                    dest = os.path.join(raw_tmp_dir, content_id + ".rap"),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

        # Extract pkg files
        for obj in system.GetDirectoryContents(source_game_file_dir):
            if obj.endswith(".pkg"):
                pkg_file = os.path.join(source_game_file_dir, obj)
                playstation.ExtractPSNPKG(
                    pkg_file = pkg_file,
                    extract_dir = raw_tmp_dir,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

        # Touch index file
        system.TouchFile(
            src = tmp_raw_file_index,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set transformed output
        transformed_game_output = tmp_raw_file_index

    # Convert PSV PKG to raw PSV files
    elif has_pkg_to_raw_psv:

        # Copy work.bin files
        for obj in system.GetDirectoryContents(source_game_file_dir):
            if obj.endswith(".work.bin"):
                work_bin_file = os.path.join(source_game_file_dir, obj)
                system.CopyFileOrDirectory(
                    src = os.path.join(source_game_file_dir, obj),
                    dest = os.path.join(raw_tmp_dir, "work.bin"),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

        # Extract pkg files
        for obj in system.GetDirectoryContents(source_game_file_dir):
            if obj.endswith(".pkg"):
                pkg_file = os.path.join(source_game_file_dir, obj)
                playstation.ExtractPSNPKG(
                    pkg_file = pkg_file,
                    extract_dir = raw_tmp_dir,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

        # Touch index file
        system.TouchFile(
            src = tmp_raw_file_index,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set transformed output
        transformed_game_output = tmp_raw_file_index

    ######################################################
    # Phase 4: Install and/or extract exe files
    ######################################################

    # Convert EXE to install files
    if has_exe_to_install:

        # Check for existing install image
        if not os.path.exists(cached_install_file):

            # Create install image
            success = installer.InstallComputerGame(
                json_file = source_json_file,
                output_image = tmp_install_file,
                keep_setup_files = keep_setup_files,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to install computer game")

            # Create install dir
            system.MakeDirectory(
                dir = cached_install_dir,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

            # Backup install image
            system.CopyFileOrDirectory(
                src = tmp_install_file,
                dest = cached_install_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Unpack install image
        success = install.UnpackInstallImage(
            input_image = cached_install_file,
            output_dir = raw_tmp_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return (False, "Unable to unpack install image")

        # Touch index file
        system.TouchFile(
            src = tmp_raw_file_index,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set transformed output
        transformed_game_output = tmp_raw_file_index

    # Convert EXE to plain files
    elif has_exe_to_raw_plain:

        # Get extract file
        extract_file = os.path.join(source_game_file_dir, source_game_file_basename + ".7z.001")
        if not os.path.exists(extract_file):
            extract_file = os.path.join(source_game_file_dir, source_game_file_basename + ".exe")
            if not os.path.exists(extract_file):
                return (False, "Unable to find corresponding extract file")

        # Extract file
        success = archive.ExtractArchive(
            archive_file = extract_file,
            extract_dir = os.path.join(raw_tmp_dir, gameinfo.DeriveRegularNameFromGameName(game_name)),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            return (False, "Unable to extract game")

        # Touch index file
        system.TouchFile(
            src = tmp_raw_file_index,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Set transformed output
        transformed_game_output = tmp_raw_file_index

    ######################################################

    # No transformation was able to be done, so default to the original file
    if not os.path.exists(transformed_game_output):
        return (True, source_game_file)

    # Move transformed output
    system.MoveContents(
        src = system.GetFilenameDirectory(transformed_game_output),
        dest = output_dir,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get new transformed file
    new_transformed_game_output = os.path.join(output_dir, system.GetFilenameFile(transformed_game_output))

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Return path to transformed output
    return (True, new_transformed_game_output)
