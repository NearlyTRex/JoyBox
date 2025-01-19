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
import playlist
import iso
import chd
import playstation
import xbox

###########################################################

# Transform computer programs
def TransformComputerPrograms(
    game_info,
    source_file,
    output_dir,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_category = game_info.get_category()
    game_subcategory = game_info.get_subcategory()

    # Get paths
    output_extract_dir = system.JoinPaths(output_dir, gameinfo.DeriveRegularNameFromGameName(game_name))
    output_extract_index_file = system.JoinPaths(output_extract_dir, config.raw_files_index)
    output_install_file = system.JoinPaths(output_dir, game_name + ".install")
    cached_install_dir = environment.GetCacheGamingInstallDir(game_category, game_subcategory, game_name)
    cached_install_file = system.JoinPaths(cached_install_dir, game_name + ".install")

    # Make directories
    system.MakeDirectory(
        dir = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        dir = cached_install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get pre-packaged archive
    prepackaged_archive = system.JoinPaths(system.GetFilenameDirectory(source_file), game_name + ".7z")
    if not os.path.exists(prepackaged_archive):
        prepackaged_archive = system.JoinPaths(system.GetFilenameDirectory(source_file), game_name + ".7z.001")
        if not os.path.exists(prepackaged_archive):
            prepackaged_archive = system.JoinPaths(system.GetFilenameDirectory(source_file), game_name + ".exe")

    # Pre-packaged archive
    if system.IsPathFile(prepackaged_archive):

        # Extract file
        success = archive.ExtractArchive(
            archive_file = prepackaged_archive,
            extract_dir = output_extract_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return (False, "Unable to extract game")

    # Normal installer files
    else:

        # Check for existing install image
        if not os.path.exists(cached_install_file):

            # Create install image
            success = installer.InstallComputerGame(
                game_info = game_info,
                output_image = output_install_file,
                keep_setup_files = keep_setup_files,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to install computer game")

            # Backup install image
            success = system.SmartTransfer(
                src = output_install_file,
                dest = cached_install_file,
                delete_afterwards = True,
                show_progress = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to backup computer game install")

        # Unpack install image
        success = install.UnpackInstallImage(
            input_image = cached_install_file,
            output_dir = output_extract_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return (False, "Unable to unpack install image")

    # Touch index file
    success = system.TouchFile(
        src = output_extract_index_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to create raw index")

    # Return output
    return (True, output_extract_index_file)

###########################################################

# Transform disc images
def TransformDiscImage(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    system.MakeDirectory(
        dir = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get disc images
    disc_image_files = []
    if source_file.endswith(".chd"):
        disc_image_files = [system.GetFilenameFile(source_file)]
    if source_file.endswith(".m3u"):
        disc_image_files = playlist.ReadPlaylist(
            input_file = source_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Extract disc images
    for disc_image_file in disc_image_files:
        if disc_image_file.endswith(".chd"):
            success = chd.ExtractDiscCHD(
                chd_file = system.JoinPaths(system.GetFilenameDirectory(source_file), disc_image_file),
                binary_file = system.JoinPaths(output_dir, system.GetFilenameBasename(disc_image_file) + config.DiscImageFileType.ISO.cval()),
                toc_file = system.JoinPaths(output_dir, system.GetFilenameBasename(disc_image_file) + ".toc"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to extract disc images")

    # Write playlist
    if source_file.endswith(".m3u"):
        playlist_contents = []
        for disc_image_file in disc_image_files:
            playlist_contents += [disc_image_file.replace(".chd", ".iso")]
        success = playlist.WritePlaylist(
            output_file = system.JoinPaths(output_dir, system.GetFilenameBasename(source_file) + ".m3u"),
            playlist_contents = playlist_contents,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return (False, "Unable to write playlist")

    # Return output
    if source_file.endswith(".chd"):
        return (True, system.JoinPaths(output_dir, system.GetFilenameBasename(source_file) + config.DiscImageFileType.ISO.cval()))
    elif source_file.endswith(".m3u"):
        return (True, system.JoinPaths(output_dir, system.GetFilenameBasename(source_file) + ".m3u"))

    # No transformation was done
    return (False, source_file)

###########################################################

# Transform Xbox disc image
def TransformXboxDiscImage(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    system.MakeDirectory(
        dir = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get disc images
    disc_image_files = []
    if source_file.endswith(".iso"):
        disc_image_files = [system.GetFilenameFile(source_file)]
    if source_file.endswith(".m3u"):
        disc_image_files = playlist.ReadPlaylist(
            input_file = source_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Rewrite xbox disc images
    for disc_image_file in disc_image_files:
        if disc_image_file.endswith(".iso"):
            success = xbox.RewriteXboxISO(
                iso_file = system.JoinPaths(system.GetFilenameDirectory(source_file), disc_image_file),
                delete_original = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to rewrite xbox disc images")

    # Return output
    return (True, system.JoinPaths(output_dir, system.GetFilenameFile(source_file)))

###########################################################

# Transform PS3 disc image
def TransformPS3DiscImage(
    source_file,
    source_file_dkey,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    system.MakeDirectory(
        dir = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get disc images
    disc_image_files = []
    if source_file.endswith(".iso"):
        disc_image_files = [system.GetFilenameFile(source_file)]
    if source_file.endswith(".m3u"):
        disc_image_files = playlist.ReadPlaylist(
            input_file = source_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Extract disc images
    for disc_image_file in disc_image_files:
        if disc_image_file.endswith(".iso"):

            # Extract ps3 disc image
            success = playstation.ExtractPS3ISO(
                iso_file = system.JoinPaths(system.GetFilenameDirectory(source_file), disc_image_file),
                dkey_file = source_file_dkey,
                extract_dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to extract ps3 disc images")

            # Extract ps3 pkg files
            for pkg_file in system.BuildFileListByExtensions(output_dir, extensions = [".PKG", ".pkg"]):
                should_extract = False
                if "PS3_GAME/PKGDIR" in pkg_file:
                    should_extract = True
                if "PS3_EXTRA" in pkg_file:
                    should_extract = True
                if should_extract:
                    pkg_dir = system.GetFilenameDirectory(pkg_file)
                    pkg_name = system.GetFilenameBasename(pkg_file)
                    success = playstation.ExtractPSNPKG(
                        pkg_file = pkg_file,
                        extract_dir = system.JoinPaths(pkg_dir, pkg_name),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return (False, "Unable to extract ps3 pkg files")

    # Touch index file
    success = system.TouchFile(
        src = system.JoinPaths(output_dir, config.raw_files_index),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to create raw index")

    # Return output
    return (True, system.JoinPaths(output_dir, config.raw_files_index))

###########################################################

# Transform PS3 network package
def TransformPS3NetworkPackage(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    system.MakeDirectory(
        dir = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Copy rap files
    for obj in system.GetDirectoryContents(system.GetFilenameDirectory(source_file)):
        if obj.endswith(".rap"):
            rap_file = system.JoinPaths(system.GetFilenameDirectory(source_file), obj)
            pkg_file = system.JoinPaths(system.GetFilenameDirectory(source_file), obj.replace(".rap", ".pkg"))
            content_id = playstation.GetPSNPackageContentID(pkg_file)
            if content_id:
                success = system.CopyFileOrDirectory(
                    src = rap_file,
                    dest = system.JoinPaths(output_dir, content_id + ".rap"),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return (False, "Unable to copy rap files")

    # Extract ps3 pkg files
    for obj in system.GetDirectoryContents(system.GetFilenameDirectory(source_file)):
        if obj.endswith(".pkg"):
            pkg_file = system.JoinPaths(system.GetFilenameDirectory(source_file), obj)
            success = playstation.ExtractPSNPKG(
                pkg_file = pkg_file,
                extract_dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to extract ps3 pkg files")

    # Touch index file
    success = system.TouchFile(
        src = system.JoinPaths(output_dir, config.raw_files_index),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to create raw index")

    # Return output
    return (True, system.JoinPaths(output_dir, config.raw_files_index))

###########################################################

# Transform PSV network package
def TransformPSVNetworkPackage(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    system.MakeDirectory(
        dir = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Copy work.bin files
    for obj in system.GetDirectoryContents(system.GetFilenameDirectory(source_file)):
        if obj.endswith(".work.bin"):
            work_bin_file = system.JoinPaths(system.GetFilenameDirectory(source_file), obj)
            success = system.CopyFileOrDirectory(
                src = system.JoinPaths(system.GetFilenameDirectory(source_file), obj),
                dest = system.JoinPaths(output_dir, "work.bin"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to copy work.bin files")

    # Extract psv pkg files
    for obj in system.GetDirectoryContents(system.GetFilenameDirectory(source_file)):
        if obj.endswith(".pkg"):
            pkg_file = system.JoinPaths(system.GetFilenameDirectory(source_file), obj)
            success = playstation.ExtractPSNPKG(
                pkg_file = pkg_file,
                extract_dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to extract psv pkg files")

    # Touch index file
    success = system.TouchFile(
        src = system.JoinPaths(output_dir, config.raw_files_index),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to create raw index")

    # Return output
    return (True, system.JoinPaths(output_dir, config.raw_files_index))

###########################################################

# Transform game file
def TransformGameFile(
    game_info,
    source_dir,
    output_dir,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_category = game_info.get_category()
    game_subcategory = game_info.get_subcategory()
    game_name = game_info.get_game()
    game_transform_file = system.JoinPaths(source_dir, game_info.get_transform_file())
    game_key_file = system.JoinPaths(source_dir, game_info.get_key_file())

    # Output dir doesn't exist
    if not system.IsPathDirectory(output_dir):
        return (False, "Output directory doesn't exist")

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return (False, tmp_dir_result)

    # Transform result
    transform_success = False
    transform_result = ""

    # Computer
    if game_category == config.Category.COMPUTER:
        transform_success, transform_result = TransformComputerPrograms(
            game_info = game_info,
            source_file = transform_file,
            output_dir = tmp_dir_result,
            keep_setup_files = keep_setup_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not transform_success:
            return (False, transform_result)

    # Microsoft Xbox/Xbox 360
    elif game_subcategory in [config.Subcategory.MICROSOFT_XBOX, config.Subcategory.MICROSOFT_XBOX_360]:
        iso_success, iso_result = TransformDiscImage(
            source_file = game_transform_file,
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not iso_success:
            return (False, iso_result)
        transform_success, transform_result = TransformXboxDiscImage(
            source_file = iso_result,
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not transform_success:
            return (False, transform_result)

    # Sony PlayStation 3
    elif game_subcategory == config.Subcategory.SONY_PLAYSTATION_3:
        iso_success, iso_result = TransformDiscImage(
            source_file = game_transform_file,
            output_dir = system.JoinPaths(tmp_dir_result, "iso"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not iso_success:
            return (False, iso_result)
        transform_success, transform_result = TransformPS3DiscImage(
            source_file = iso_result,
            source_file_dkey = game_key_file,
            output_dir = system.JoinPaths(tmp_dir_result, "output"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not transform_success:
            return (False, transform_result)

    # Sony PlayStation Network - PlayStation 3
    elif game_subcategory == config.Subcategory.SONY_PLAYSTATION_NETWORK_PS3:
        transform_success, transform_result = TransformPS3NetworkPackage(
            source_file = game_transform_file,
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not transform_success:
            return (False, transform_result)

    # Sony PlayStation Network - PlayStation Vita
    elif game_subcategory == config.Subcategory.SONY_PLAYSTATION_NETWORK_PSV:
        transform_success, transform_result = TransformPSVNetworkPackage(
            source_file = game_transform_file,
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not transform_success:
            return (False, transform_result)

    # No transformation was able to be done
    if not os.path.exists(transform_result):
        return (False, "No transformation was able to be done")

    # Move transformed output out of temporary directory
    success = system.MoveContents(
        src = system.GetFilenameDirectory(transform_result),
        dest = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to move transformed output")

    # Get final result
    final_result_path = system.JoinPaths(output_dir, system.GetFilenameFile(transform_result))

    # Delete temporary directory
    system.RemoveDirectory(
        dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Return final result
    return (True, final_result_path)
