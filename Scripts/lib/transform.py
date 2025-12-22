# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import fileops
import platforms
import gameinfo
import install
import computer
import archive
import playlist
import iso
import paths
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
    output_extract_dir = paths.join_paths(output_dir, gameinfo.derive_regular_name_from_game_name(game_name))
    output_extract_index_file = paths.join_paths(output_extract_dir, config.raw_files_index)
    output_install_file = paths.join_paths(output_dir, game_name + ".install")
    cached_install_dir = environment.get_cache_gaming_install_dir(game_category, game_subcategory, game_name)
    cached_install_file = paths.join_paths(cached_install_dir, game_name + ".install")

    # Make directories
    fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    fileops.make_directory(
        src = cached_install_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get pre-packaged archive
    # TODO: This should be a separate function to get the prepackaged archive file (the one manually created because some platforms like steam only send you raw files)
    prepackaged_archive = paths.join_paths(paths.get_filename_directory(source_file), game_name + ".7z")
    if not os.path.exists(prepackaged_archive):
        prepackaged_archive = paths.join_paths(paths.get_filename_directory(source_file), game_name + ".7z.001")
        if not os.path.exists(prepackaged_archive):
            prepackaged_archive = paths.join_paths(paths.get_filename_directory(source_file), game_name + ".exe")

    # Pre-packaged archive
    if paths.is_path_file(prepackaged_archive):

        # Extract file
        success = archive.extract_archive(
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
        if not paths.does_path_exist(cached_install_file):

            # Create install image
            success = computer.SetupComputerGame(
                game_info = game_info,
                source_file = source_file,
                output_image = output_install_file,
                keep_setup_files = keep_setup_files,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to install computer game")

            # Backup install image
            success = fileops.smart_transfer(
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
    success = fileops.touch_file(
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
    fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get disc images
    disc_image_files = []
    if source_file.endswith(".chd"):
        disc_image_files = [paths.get_filename_file(source_file)]
    if source_file.endswith(".m3u"):
        disc_image_files = playlist.ReadPlaylist(
            input_file = source_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Extract disc images
    for disc_image_file in disc_image_files:
        if disc_image_file.endswith(".chd"):
            success = chd.extract_disc_chd(
                chd_file = paths.join_paths(paths.get_filename_directory(source_file), disc_image_file),
                binary_file = paths.join_paths(output_dir, paths.get_filename_basename(disc_image_file) + config.DiscImageFileType.ISO.cval()),
                toc_file = paths.join_paths(output_dir, paths.get_filename_basename(disc_image_file) + ".toc"),
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
            output_file = paths.join_paths(output_dir, paths.get_filename_basename(source_file) + ".m3u"),
            playlist_contents = playlist_contents,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return (False, "Unable to write playlist")

    # Return output
    # TODO: These kinds of functions would be better as a function (IsFileCHD, or something)
    if source_file.endswith(".chd"):
        return (True, paths.join_paths(output_dir, paths.get_filename_basename(source_file) + config.DiscImageFileType.ISO.cval()))
    elif source_file.endswith(".m3u"):
        return (True, paths.join_paths(output_dir, paths.get_filename_basename(source_file) + ".m3u"))

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
    fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get disc images
    disc_image_files = []
    if source_file.endswith(".iso"):
        disc_image_files = [paths.get_filename_file(source_file)]
    if source_file.endswith(".m3u"):
        disc_image_files = playlist.ReadPlaylist(
            input_file = source_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Rewrite xbox disc images
    for disc_image_file in disc_image_files:
        if disc_image_file.endswith(".iso"):
            success = xbox.rewrite_xbox_iso(
                iso_file = paths.join_paths(paths.get_filename_directory(source_file), disc_image_file),
                delete_original = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to rewrite xbox disc images")

    # Return output
    return (True, paths.join_paths(output_dir, paths.get_filename_file(source_file)))

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
    fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get disc images
    disc_image_files = []
    if source_file.endswith(".iso"):
        disc_image_files = [paths.get_filename_file(source_file)]
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
            success = playstation.extract_ps3_iso(
                iso_file = paths.join_paths(paths.get_filename_directory(source_file), disc_image_file),
                dkey_file = source_file_dkey,
                extract_dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to extract ps3 disc images")

            # Extract ps3 pkg files
            for pkg_file in paths.build_file_list_by_extensions(output_dir, extensions = [".PKG", ".pkg"]):
                should_extract = False
                if "PS3_GAME/PKGDIR" in pkg_file:
                    should_extract = True
                if "PS3_EXTRA" in pkg_file:
                    should_extract = True
                if should_extract:
                    pkg_dir = paths.get_filename_directory(pkg_file)
                    pkg_name = paths.get_filename_basename(pkg_file)
                    success = playstation.extract_psn_pkg(
                        pkg_file = pkg_file,
                        extract_dir = paths.join_paths(pkg_dir, pkg_name),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return (False, "Unable to extract ps3 pkg files")

    # Touch index file
    success = fileops.touch_file(
        src = paths.join_paths(output_dir, config.raw_files_index),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to create raw index")

    # Return output
    return (True, paths.join_paths(output_dir, config.raw_files_index))

###########################################################

# Transform PS3 network package
def TransformPS3NetworkPackage(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Copy rap files
    for obj in paths.get_directory_contents(paths.get_filename_directory(source_file)):
        if obj.endswith(".rap"):
            rap_file = paths.join_paths(paths.get_filename_directory(source_file), obj)
            pkg_file = paths.join_paths(paths.get_filename_directory(source_file), obj.replace(".rap", ".pkg"))
            content_id = playstation.get_psn_package_content_id(pkg_file)
            if content_id:
                success = fileops.copy_file_or_directory(
                    src = rap_file,
                    dest = paths.join_paths(output_dir, content_id + ".rap"),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return (False, "Unable to copy rap files")

    # Extract ps3 pkg files
    for obj in paths.get_directory_contents(paths.get_filename_directory(source_file)):
        if obj.endswith(".pkg"):
            pkg_file = paths.join_paths(paths.get_filename_directory(source_file), obj)
            success = playstation.extract_psn_pkg(
                pkg_file = pkg_file,
                extract_dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to extract ps3 pkg files")

    # Touch index file
    success = fileops.touch_file(
        src = paths.join_paths(output_dir, config.raw_files_index),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to create raw index")

    # Return output
    return (True, paths.join_paths(output_dir, config.raw_files_index))

###########################################################

# Transform PSV network package
def TransformPSVNetworkPackage(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Copy work.bin files
    for obj in paths.get_directory_contents(paths.get_filename_directory(source_file)):
        if obj.endswith(".work.bin"):
            work_bin_file = paths.join_paths(paths.get_filename_directory(source_file), obj)
            success = fileops.copy_file_or_directory(
                src = paths.join_paths(paths.get_filename_directory(source_file), obj),
                dest = paths.join_paths(output_dir, "work.bin"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to copy work.bin files")

    # Extract psv pkg files
    for obj in paths.get_directory_contents(paths.get_filename_directory(source_file)):
        if obj.endswith(".pkg"):
            pkg_file = paths.join_paths(paths.get_filename_directory(source_file), obj)
            success = playstation.extract_psn_pkg(
                pkg_file = pkg_file,
                extract_dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to extract psv pkg files")

    # Touch index file
    success = fileops.touch_file(
        src = paths.join_paths(output_dir, config.raw_files_index),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to create raw index")

    # Return output
    return (True, paths.join_paths(output_dir, config.raw_files_index))

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

    # Output dir doesn't exist
    if not paths.is_path_directory(output_dir):
        return (False, "Output directory doesn't exist")

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
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
            source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
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
            source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
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
            source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
            output_dir = paths.join_paths(tmp_dir_result, "iso"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not iso_success:
            return (False, iso_result)
        transform_success, transform_result = TransformPS3DiscImage(
            source_file = iso_result,
            source_file_dkey = paths.join_paths(source_dir, game_info.get_key_file()),
            output_dir = paths.join_paths(tmp_dir_result, "output"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not transform_success:
            return (False, transform_result)

    # Sony PlayStation Network - PlayStation 3
    elif game_subcategory == config.Subcategory.SONY_PLAYSTATION_NETWORK_PS3:
        transform_success, transform_result = TransformPS3NetworkPackage(
            source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not transform_success:
            return (False, transform_result)

    # Sony PlayStation Network - PlayStation Vita
    elif game_subcategory == config.Subcategory.SONY_PLAYSTATION_NETWORK_PSV:
        transform_success, transform_result = TransformPSVNetworkPackage(
            source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
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
    success = fileops.move_contents(
        src = paths.get_filename_directory(transform_result),
        dest = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to move transformed output")

    # Get final result
    final_result_path = paths.join_paths(output_dir, paths.get_filename_file(transform_result))

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Return final result
    return (True, final_result_path)
