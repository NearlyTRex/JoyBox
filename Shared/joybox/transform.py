# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import gamenaming
from joybox import install
from joybox import computer
from joybox import archive
from joybox import playlist
from joybox import paths
from joybox import chd
from joybox import playstation
from joybox import xbox

###########################################################

# Find the archive packed by hand next to a game's files, for stores like Steam
# that only send raw files: a 7z, the first part of a split 7z, or a self-extracting exe
def find_prepackaged_archive(source_file, game_name):
    source_dir = paths.get_filename_directory(source_file)
    for extension in (".7z", ".7z.001"):
        candidate = paths.join_paths(source_dir, game_name + extension)
        if os.path.exists(candidate):
            return candidate
    return paths.join_paths(source_dir, game_name + ".exe")

# Make output_dir, leaving any failure to the steps that write into it
def _make_output_dir(output_dir, verbose, pretend_run, exit_on_failure):
    fileops.make_directory(
        src = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# The disc image files of a source: itself when is_single_image, those its playlist lists, or none
def _list_disc_image_files(source_file, is_single_image, verbose, pretend_run, exit_on_failure):
    disc_image_files = []
    if is_single_image:
        disc_image_files = [paths.get_filename_file(source_file)]
    if playlist.is_playlist_file(source_file):
        disc_image_files = playlist.read_playlist(
            input_file = source_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return disc_image_files

# Touch the raw files index in output_dir; (True, index file) or (False, error)
def _touch_raw_index(output_dir, verbose, pretend_run, exit_on_failure):
    success = fileops.touch_file(
        src = paths.join_paths(output_dir, config.RAW_FILES_INDEX),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to create raw index")
    return (True, paths.join_paths(output_dir, config.RAW_FILES_INDEX))

# Unpack a computer game into output_dir from its pre-packaged archive, or by running its installers
# into an install image that is backed up then unpacked; returns (success, index file or error)
def transform_computer_programs(
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
    output_extract_dir = paths.join_paths(output_dir, gamenaming.derive_regular_name_from_game_name(game_name))
    output_install_file = paths.join_paths(output_dir, game_name + ".install")
    cached_install_dir = environment.get_cache_gaming_install_dir(game_category, game_subcategory, game_name)
    cached_install_file = paths.join_paths(cached_install_dir, game_name + ".install")

    # Make directories
    _make_output_dir(output_dir, verbose, pretend_run, exit_on_failure)
    _make_output_dir(cached_install_dir, verbose, pretend_run, exit_on_failure)

    # Unpack game files
    error = _unpack_computer_game(
        game_info, game_name, source_file, output_install_file, cached_install_file, output_extract_dir,
        keep_setup_files, verbose, pretend_run, exit_on_failure)
    if error:
        return (False, error)

    # Touch index file
    return _touch_raw_index(output_extract_dir, verbose, pretend_run, exit_on_failure)

# Unpack a computer game from its pre-packaged archive when there is one, otherwise from its install image
# Returns the error, or None on success
def _unpack_computer_game(game_info, game_name, source_file, output_install_file, cached_install_file, output_extract_dir, keep_setup_files, verbose, pretend_run, exit_on_failure):

    # Get pre-packaged archive
    prepackaged_archive = find_prepackaged_archive(source_file, game_name)

    # Pre-packaged archive
    if paths.is_path_file(prepackaged_archive):
        success = archive.extract_archive(
            archive_file = prepackaged_archive,
            extract_dir = output_extract_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return None if success else "Unable to extract game"

    # Normal installer files
    return _unpack_installed_game(
        game_info, source_file, output_install_file, cached_install_file, output_extract_dir,
        keep_setup_files, verbose, pretend_run, exit_on_failure)

# Unpack the cached install image into output_extract_dir, first installing and caching it when missing
# Returns the error, or None on success
def _unpack_installed_game(game_info, source_file, output_install_file, cached_install_file, output_extract_dir, keep_setup_files, verbose, pretend_run, exit_on_failure):

    # Check for existing install image
    if not paths.does_path_exist(cached_install_file):
        error = _create_cached_install_image(
            game_info, source_file, output_install_file, cached_install_file,
            keep_setup_files, verbose, pretend_run, exit_on_failure)
        if error:
            return error

    # Unpack install image
    success = install.unpack_install_image(
        input_image = cached_install_file,
        output_dir = output_extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return "Unable to unpack install image"
    return None

# Run the game's installers into an install image and move it to the install cache; the error, or None
def _create_cached_install_image(game_info, source_file, output_install_file, cached_install_file, keep_setup_files, verbose, pretend_run, exit_on_failure):

    # Create install image
    success = computer.setup_computer_game(
        game_info = game_info,
        source_file = source_file,
        output_image = output_install_file,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return "Unable to install computer game"

    # Backup install image
    success = filebulk.smart_transfer(
        src = output_install_file,
        dest = cached_install_file,
        delete_afterwards = True,
        show_progress = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return "Unable to backup computer game install"
    return None

###########################################################

# Extract a CHD, or each CHD a playlist lists, to ISO in output_dir, rewriting the playlist to match
# Returns (True, iso or m3u path), or (False, source_file) when there was nothing to extract
def transform_disc_image(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    _make_output_dir(output_dir, verbose, pretend_run, exit_on_failure)

    # Get disc images
    disc_image_files = _list_disc_image_files(source_file, chd.is_chd_file(source_file), verbose, pretend_run, exit_on_failure)

    # Extract disc images
    for disc_image_file in disc_image_files:
        if chd.is_chd_file(disc_image_file):
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
    if playlist.is_playlist_file(source_file):
        success = _write_iso_playlist(source_file, output_dir, disc_image_files, verbose, pretend_run, exit_on_failure)
        if not success:
            return (False, "Unable to write playlist")

    # Return output
    if chd.is_chd_file(source_file):
        return (True, paths.join_paths(output_dir, paths.get_filename_basename(source_file) + config.DiscImageFileType.ISO.cval()))
    if playlist.is_playlist_file(source_file):
        return (True, paths.join_paths(output_dir, paths.get_filename_basename(source_file) + ".m3u"))

    # No transformation was done
    return (False, source_file)

# Write an m3u in output_dir, named after the source playlist, listing its CHDs as the extracted ISOs
def _write_iso_playlist(source_file, output_dir, disc_image_files, verbose, pretend_run, exit_on_failure):
    playlist_contents = []
    for disc_image_file in disc_image_files:
        playlist_contents += [disc_image_file.replace(".chd", ".iso")]
    return playlist.write_playlist(
        output_file = paths.join_paths(output_dir, paths.get_filename_basename(source_file) + ".m3u"),
        playlist_contents = playlist_contents,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################

# Rewrite an Xbox ISO, or each ISO a playlist lists, in place with extract-xiso; returns (success, path or error)
def transform_xbox_disc_image(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    _make_output_dir(output_dir, verbose, pretend_run, exit_on_failure)

    # Get disc images
    disc_image_files = _list_disc_image_files(source_file, source_file.endswith(".iso"), verbose, pretend_run, exit_on_failure)

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

# Extract a PS3 ISO with its disc key into output_dir, then the pkg files on it; returns (success, index file or error)
def transform_ps3_disc_image(
    source_file,
    source_file_dkey,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    _make_output_dir(output_dir, verbose, pretend_run, exit_on_failure)

    # Get disc images
    disc_image_files = _list_disc_image_files(source_file, source_file.endswith(".iso"), verbose, pretend_run, exit_on_failure)

    # Extract disc images
    iso_files = [disc_image_file for disc_image_file in disc_image_files if disc_image_file.endswith(".iso")]
    for iso_file in iso_files:
        success = playstation.extract_ps3_iso(
            iso_file = paths.join_paths(paths.get_filename_directory(source_file), iso_file),
            dkey_file = source_file_dkey,
            extract_dir = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return (False, "Unable to extract ps3 disc images")

    # Extract the game and extra pkgs the discs hold, once for all discs
    if iso_files and not _extract_ps3_disc_packages(output_dir, verbose, pretend_run, exit_on_failure):
        return (False, "Unable to extract ps3 pkg files")

    # Touch index file
    return _touch_raw_index(output_dir, verbose, pretend_run, exit_on_failure)

# Extract each game and extra pkg of extracted PS3 discs beside itself; False at the first that fails
def _extract_ps3_disc_packages(output_dir, verbose, pretend_run, exit_on_failure):
    for pkg_file in paths.build_file_list_by_extensions(output_dir, extensions = [".PKG", ".pkg"]):
        should_extract = False
        if "PS3_GAME/PKGDIR" in pkg_file:
            should_extract = True
        if "PS3_EXTRA" in pkg_file:
            should_extract = True
        if not should_extract:
            continue
        pkg_dir = paths.get_filename_directory(pkg_file)
        pkg_name = paths.get_filename_basename(pkg_file)
        success = playstation.extract_psn_pkg(
            pkg_file = pkg_file,
            extract_dir = paths.join_paths(pkg_dir, pkg_name),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

###########################################################

# Copy the .rap licenses beside a PS3 pkg and extract the pkgs into output_dir; returns (success, index file or error)
def transform_ps3_network_package(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    _make_output_dir(output_dir, verbose, pretend_run, exit_on_failure)

    # Copy rap files
    if not _copy_rap_files(source_file, output_dir, verbose, pretend_run, exit_on_failure):
        return (False, "Unable to copy rap files")

    # Extract ps3 pkg files
    if not _extract_sibling_pkg_files(source_file, output_dir, verbose, pretend_run, exit_on_failure):
        return (False, "Unable to extract ps3 pkg files")

    # Touch index file
    return _touch_raw_index(output_dir, verbose, pretend_run, exit_on_failure)

# Copy each .rap beside the source into output_dir, named by its pkg's content id; False at the first failed copy
# A .rap whose pkg has no content id is skipped
def _copy_rap_files(source_file, output_dir, verbose, pretend_run, exit_on_failure):
    for obj in paths.get_directory_contents(paths.get_filename_directory(source_file)):
        if not obj.endswith(".rap"):
            continue
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
                return False
    return True

# Extract each .pkg beside the source into output_dir; False at the first that fails
def _extract_sibling_pkg_files(source_file, output_dir, verbose, pretend_run, exit_on_failure):
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
                return False
    return True

###########################################################

# Copy the .work.bin licenses beside a Vita pkg and extract the pkgs into output_dir; returns (success, index file or error)
def transform_psv_network_package(
    source_file,
    output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    _make_output_dir(output_dir, verbose, pretend_run, exit_on_failure)

    # Copy work.bin files
    for obj in paths.get_directory_contents(paths.get_filename_directory(source_file)):
        if obj.endswith(".work.bin"):
            success = fileops.copy_file_or_directory(
                src = paths.join_paths(paths.get_filename_directory(source_file), obj),
                dest = paths.join_paths(output_dir, "work.bin"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return (False, "Unable to copy work.bin files")

    # Extract psv pkg files
    if not _extract_sibling_pkg_files(source_file, output_dir, verbose, pretend_run, exit_on_failure):
        return (False, "Unable to extract psv pkg files")

    # Touch index file
    return _touch_raw_index(output_dir, verbose, pretend_run, exit_on_failure)

###########################################################

# Turn a game's stored file into its playable form in a temp dir, by platform, then move it into output_dir
# Returns (success, output path or error)
def transform_game_file(
    game_info,
    source_dir,
    output_dir,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Output dir doesn't exist
    if not paths.is_path_directory(output_dir):
        return (False, "Output directory doesn't exist")

    # Transform in a temporary directory
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return (False, "Unable to create temporary directory")
        return transform_game_file_in(
            game_info = game_info,
            source_dir = source_dir,
            output_dir = output_dir,
            tmp_dir_result = tmp_dir,
            keep_setup_files = keep_setup_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Transform game file using a temporary directory
def transform_game_file_in(
    game_info,
    source_dir,
    output_dir,
    tmp_dir_result,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Transform by platform
    transform_success, transform_result = _transform_by_platform(
        game_info, source_dir, tmp_dir_result, keep_setup_files, verbose, pretend_run, exit_on_failure)
    if not transform_success:
        return (False, transform_result)

    # No transformation was able to be done
    if not os.path.exists(transform_result):
        return (False, "No transformation was able to be done")

    # Move transformed output out of temporary directory
    success = filebulk.move_contents(
        src = paths.get_filename_directory(transform_result),
        dest = output_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "Unable to move transformed output")

    # Return final result
    return (True, paths.join_paths(output_dir, paths.get_filename_file(transform_result)))

# Run the transform for the game's platform into tmp_dir_result; (success, output path or error)
# A platform with no transform gives the no-transformation error
def _transform_by_platform(game_info, source_dir, tmp_dir_result, keep_setup_files, verbose, pretend_run, exit_on_failure):
    game_category = game_info.get_category()
    game_subcategory = game_info.get_subcategory()
    if game_category == config.Category.COMPUTER:
        return transform_computer_programs(
            game_info = game_info,
            source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
            output_dir = tmp_dir_result,
            keep_setup_files = keep_setup_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if game_subcategory in [config.Subcategory.MICROSOFT_XBOX, config.Subcategory.MICROSOFT_XBOX_360]:
        return _transform_xbox_game(game_info, source_dir, tmp_dir_result, verbose, pretend_run, exit_on_failure)
    if game_subcategory == config.Subcategory.SONY_PLAYSTATION_3:
        return _transform_ps3_game(game_info, source_dir, tmp_dir_result, verbose, pretend_run, exit_on_failure)
    if game_subcategory == config.Subcategory.SONY_PLAYSTATION_NETWORK_PS3:
        return transform_ps3_network_package(
            source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if game_subcategory == config.Subcategory.SONY_PLAYSTATION_NETWORK_PSV:
        return transform_psv_network_package(
            source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return (False, "No transformation was able to be done")

# Extract an Xbox game's CHD to ISO, then rewrite the ISO with extract-xiso; (success, path or error)
def _transform_xbox_game(game_info, source_dir, tmp_dir_result, verbose, pretend_run, exit_on_failure):
    iso_success, iso_result = transform_disc_image(
        source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
        output_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not iso_success:
        return (False, iso_result)
    return transform_xbox_disc_image(
        source_file = iso_result,
        output_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Extract a PS3 game's CHD to ISO under iso, then the ISO and its pkgs under output; (success, path or error)
def _transform_ps3_game(game_info, source_dir, tmp_dir_result, verbose, pretend_run, exit_on_failure):
    iso_success, iso_result = transform_disc_image(
        source_file = paths.join_paths(source_dir, game_info.get_transform_file()),
        output_dir = paths.join_paths(tmp_dir_result, "iso"),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not iso_success:
        return (False, iso_result)
    return transform_ps3_disc_image(
        source_file = iso_result,
        source_file_dkey = paths.join_paths(source_dir, game_info.get_key_file()),
        output_dir = paths.join_paths(tmp_dir_result, "output"),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
