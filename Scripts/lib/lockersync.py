# Imports
import os
import os.path
import sys
import fnmatch
from collections import defaultdict

# Local imports
import config
import system
import logger
import paths
import fileops
import hashing
import cryption
import lockerinfo
import sync
import editorprompt

# Load existing hash files from hash output directory
def load_existing_hash_map(
    hash_output_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    all_hashes = {}
    if not paths.does_path_exist(hash_output_dir):
        return all_hashes
    for hash_file in paths.build_file_list(hash_output_dir, use_relative_paths = False):
        if paths.get_filename_file(hash_file) == "hashes.json":
            if verbose:
                logger.log_info("Loading hash file: %s" % hash_file)
            hash_contents = hashing.read_hash_file(
                src = hash_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if hash_contents:
                all_hashes.update(hash_contents)
    return all_hashes

# Build authoritative hash map from primary locker
def build_authoritative_hash_map(
    source_path,
    passphrase,
    output_hash_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Build file list from source
    if verbose:
        logger.log_info("Building authoritative hash map from: %s" % source_path)
    all_files = paths.build_file_list(source_path, use_relative_paths = True)
    if not all_files:
        logger.log_warning("No files found in source path: %s" % source_path)
        return {}

    # Group files by top-level subfolder for separate hash files
    files_by_subfolder = defaultdict(list)
    for file_path in all_files:
        parts = file_path.split(os.sep)
        if len(parts) >= 2:
            subfolder = paths.join_paths(parts[0], parts[1]) if len(parts) >= 2 else parts[0]
        else:
            subfolder = parts[0] if parts else "root"
        files_by_subfolder[subfolder].append(file_path)

    # Build hash map for each subfolder
    all_hashes = {}
    for subfolder, files in files_by_subfolder.items():
        hash_file = paths.join_paths(output_hash_dir, subfolder, "hashes.json")
        if verbose:
            logger.log_info("Processing subfolder: %s (%d files)" % (subfolder, len(files)))

        # Load existing hashes if available
        hash_contents = {}
        if paths.is_path_file(hash_file):
            hash_contents = hashing.read_hash_file(
                src = hash_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Hash each file
        for file_path in files:
            full_path = paths.join_paths(source_path, file_path)

            # Check if file needs rehashing (based on mtime/size)
            file_key = file_path
            if file_key in hash_contents:
                existing = hash_contents[file_key]
                current_mtime = int(os.path.getmtime(full_path))
                current_size = os.path.getsize(full_path)
                if existing.get("mtime") == current_mtime and existing.get("size") == current_size:
                    all_hashes[file_path] = existing
                    continue

            # Calculate hash
            hash_data = hashing.calculate_hash(
                src = file_path,
                base_path = source_path,
                passphrase = passphrase,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if hash_data:
                hash_contents[file_path] = hash_data
                all_hashes[file_path] = hash_data

        # Write updated hash file
        if not pretend_run:
            fileops.make_directory(
                src = paths.get_filename_directory(hash_file),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            hashing.write_hash_file(
                src = hash_file,
                hash_contents = hash_contents,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    return all_hashes

# Check if path matches any exclude pattern
def matches_exclude_pattern(file_path, exclude_patterns):
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(file_path, pattern):
            return True
        parts = file_path.split(os.sep)
        for i in range(len(parts)):
            partial = os.sep.join(parts[:i+1])
            if fnmatch.fnmatch(partial, pattern.rstrip("/**")):
                return True
    return False

# Build sync actions for a secondary locker
def build_sync_actions(
    authoritative_hashes,
    secondary_path,
    exclude_patterns = [],
    decrypt_on_sync = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Build list of existing files on secondary
    actions = []
    secondary_files = set()
    if paths.does_path_exist(secondary_path):
        for file_path in paths.build_file_list(secondary_path, use_relative_paths = True):
            secondary_files.add(file_path)

    # Process each file in authoritative source
    for auth_path, auth_data in authoritative_hashes.items():
        is_encrypted = bool(auth_data.get("hash_enc"))

        # Skip files matching exclude patterns
        if matches_exclude_pattern(auth_path, exclude_patterns):
            continue

        # If not decrypting on sync, skip encrypted files
        if not decrypt_on_sync and is_encrypted:
            continue

        # Determine target path
        if decrypt_on_sync and is_encrypted:
            target_path = paths.join_paths(auth_data["dir"], auth_data["filename"])
        else:
            target_path = auth_path
        target_filename = auth_data["filename"]

        # Check if file exists on secondary
        full_target_path = paths.join_paths(secondary_path, target_path)
        if target_path in secondary_files or paths.does_path_exist(full_target_path):

            # File exists - check if hash matches
            if paths.does_path_exist(full_target_path):
                existing_hash = hashing.calculate_file_xxh3(
                    src = full_target_path,
                    verbose = False,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if existing_hash != auth_data["hash"]:

                    # Hash differs - needs update
                    if is_encrypted and decrypt_on_sync:
                        actions.append({
                            "type": config.SyncActionType.UPDATE_DECRYPT,
                            "src": auth_path,
                            "dest": target_path,
                            "src_data": auth_data
                        })
                    else:
                        actions.append({
                            "type": config.SyncActionType.UPDATE,
                            "src": auth_path,
                            "dest": target_path,
                            "src_data": auth_data
                        })
            secondary_files.discard(target_path)
        else:

            # File doesn't exist - needs copy
            if is_encrypted and decrypt_on_sync:
                actions.append({
                    "type": config.SyncActionType.COPY_DECRYPT,
                    "src": auth_path,
                    "dest": target_path,
                    "src_data": auth_data
                })
            else:
                actions.append({
                    "type": config.SyncActionType.COPY,
                    "src": auth_path,
                    "dest": target_path,
                    "src_data": auth_data
                })

    # Remaining files in secondary_files are orphans (not in authoritative)
    for orphan_path in secondary_files:
        actions.append({
            "type": config.SyncActionType.DELETE,
            "path": orphan_path,
            "src_data": None
        })
    return actions

# Collapse file paths to parent folders when all files in folder are included
def collapse_to_folders(actions, secondary_path):

    # Group actions by type and parent directory
    actions_by_type_and_dir = defaultdict(lambda: defaultdict(list))
    for action in actions:
        action_type = action["type"]
        if action_type == config.SyncActionType.DELETE:
            path = action.get("path", "")
        else:
            path = action.get("dest", action.get("src", ""))
        parent_dir = paths.get_filename_directory(path)
        actions_by_type_and_dir[action_type][parent_dir].append(action)

    # Check each directory - if all files are included, collapse to folder
    collapsed_actions = []
    processed_dirs = set()
    for action_type, dirs in actions_by_type_and_dir.items():
        for parent_dir, dir_actions in dirs.items():
            if not parent_dir or parent_dir in processed_dirs:
                continue

            # Count files in the actual directory on secondary
            full_dir = paths.join_paths(secondary_path, parent_dir)
            if paths.does_path_exist(full_dir) and paths.is_path_directory(full_dir):
                actual_files = list(paths.build_file_list(full_dir, use_relative_paths = True))

                # If all files in directory are in our action list, collapse
                if len(dir_actions) >= len(actual_files) and len(actual_files) > 1:
                    collapsed_actions.append({
                        "type": action_type,
                        "path": parent_dir + "/",
                        "is_folder": True,
                        "file_count": len(dir_actions)
                    })
                    processed_dirs.add(parent_dir)
                    continue

            # Not collapsed - add individual actions
            collapsed_actions.extend(dir_actions)
    return collapsed_actions

# Generate action file content for editor
def generate_action_file_content(actions, target_name, include_orphans = True):

    # Group actions by type
    copy_actions = [a for a in actions if a["type"] == config.SyncActionType.COPY]
    decrypt_actions = [a for a in actions if a["type"] == config.SyncActionType.COPY_DECRYPT]
    update_actions = [a for a in actions if a["type"] == config.SyncActionType.UPDATE]
    update_decrypt_actions = [a for a in actions if a["type"] == config.SyncActionType.UPDATE_DECRYPT]
    delete_actions = [a for a in actions if a["type"] == config.SyncActionType.DELETE]

    # Build sections
    sections = []

    # New files section
    if copy_actions or decrypt_actions:
        items = []
        for action in copy_actions:
            path = action.get("path", action.get("dest", ""))
            items.append("%s %s" % (config.SyncActionType.COPY.upper(), path))
        for action in decrypt_actions:
            src = action.get("src", "")
            dest = action.get("dest", "")
            items.append("%s %s -> %s" % (config.SyncActionType.COPY_DECRYPT.upper(), src, dest))
        sections.append({
            "title": "NEW FILES (%d plain + %d encrypted)" % (len(copy_actions), len(decrypt_actions)),
            "items": items
        })

    # Updated files section
    if update_actions or update_decrypt_actions:
        items = []
        for action in update_actions:
            path = action.get("path", action.get("dest", ""))
            items.append("%s %s" % (config.SyncActionType.UPDATE.upper(), path))
        for action in update_decrypt_actions:
            src = action.get("src", "")
            dest = action.get("dest", "")
            items.append("%s %s -> %s" % (config.SyncActionType.UPDATE_DECRYPT.upper(), src, dest))
        sections.append({
            "title": "UPDATED FILES (%d)" % (len(update_actions) + len(update_decrypt_actions)),
            "items": items
        })

    # Orphan files section (commented out by default)
    if include_orphans and delete_actions:
        items = []
        for action in delete_actions:
            path = action.get("path", "")
            items.append("%s %s" % (config.SyncActionType.DELETE.upper(), path))
        sections.append({
            "title": "ORPHAN FILES (exist on %s but NOT in authoritative)" % target_name,
            "description": "Uncomment to delete, leave commented to keep",
            "items": items,
            "commented": True
        })

    # Generate using editorprompt module
    return editorprompt.generate_action_file(
        sections = sections,
        header_lines = [
            "%s Sync Actions" % target_name,
            "Lines starting with # are ignored",
            "Delete lines or comment them out to skip actions",
            "Save and close editor to proceed, or delete all lines to abort"
        ])

# Open editor for user to review and modify actions
def open_editor_for_sync_actions(
    actions,
    target_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    content = generate_action_file_content(actions, target_name)
    return editorprompt.open_editor_for_actions(
        content = content,
        prefix = "locker_sync_",
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Execute sync actions
def execute_sync_actions(
    actions,
    source_path,
    target_path,
    passphrase,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Run sync actions
    success_count = 0
    fail_count = 0
    for action in actions:
        # Normalize action type to enum
        raw_type = action.get("type", "")
        if isinstance(raw_type, str):
            action_type = config.SyncActionType.from_string(raw_type)
        else:
            action_type = raw_type

        # Sync copy
        if action_type == config.SyncActionType.COPY:
            src = paths.join_paths(source_path, action.get("path", action.get("src", "")))
            dest = paths.join_paths(target_path, action.get("path", action.get("dest", "")))
            if verbose:
                logger.log_info("Copying: %s -> %s" % (src, dest))
            success = fileops.smart_copy(
                src = src,
                dest = dest,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if success:
                success_count += 1
            else:
                fail_count += 1

        # Sync decrypt
        elif action_type == config.SyncActionType.COPY_DECRYPT:
            src = paths.join_paths(source_path, action.get("src", ""))
            dest = paths.join_paths(target_path, action.get("dest", ""))
            if verbose:
                logger.log_info("Decrypting: %s -> %s" % (src, dest))
            fileops.make_directory(
                src = paths.get_filename_directory(dest),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = cryption.decrypt_file(
                src = src,
                passphrase = passphrase,
                output_file = dest,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if success:
                success_count += 1
            else:
                fail_count += 1

        # Sync update
        elif action_type == config.SyncActionType.UPDATE:
            src = paths.join_paths(source_path, action.get("path", action.get("src", "")))
            dest = paths.join_paths(target_path, action.get("path", action.get("dest", "")))
            if verbose:
                logger.log_info("Updating: %s -> %s" % (src, dest))
            success = fileops.smart_copy(
                src = src,
                dest = dest,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if success:
                success_count += 1
            else:
                fail_count += 1

        # Sync update decrypt
        elif action_type == config.SyncActionType.UPDATE_DECRYPT:
            src = paths.join_paths(source_path, action.get("src", ""))
            dest = paths.join_paths(target_path, action.get("dest", ""))
            if verbose:
                logger.log_info("Decrypting (update): %s -> %s" % (src, dest))
            success = cryption.decrypt_file(
                src = src,
                passphrase = passphrase,
                output_file = dest,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if success:
                success_count += 1
            else:
                fail_count += 1

        # Sync delete
        elif action_type == config.SyncActionType.DELETE:
            target = paths.join_paths(target_path, action.get("path", ""))
            if verbose:
                logger.log_info("Deleting: %s" % target)
            if paths.is_path_directory(target):
                success = fileops.remove_directory(
                    src = target,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            else:
                success = fileops.remove_file(
                    src = target,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
            if success:
                success_count += 1
            else:
                fail_count += 1

    # All done
    logger.log_info("Sync complete: %d succeeded, %d failed" % (success_count, fail_count))
    return fail_count == 0

# Verify prerequisites for sync
def verify_prerequisites(
    primary_locker_info,
    secondary_locker_infos,
    verbose = False):

    # Check primary mount
    primary_path = primary_locker_info.get_remote_mount_path()
    if not primary_path or not paths.does_path_exist(primary_path):
        logger.log_error("Primary locker mount not found: %s" % primary_path)
        return False

    # Check each secondary
    for sec_info in secondary_locker_infos:
        if sec_info.is_local_only():
            local_path = sec_info.get_local_path()
            if not local_path or not paths.does_path_exist(local_path):
                logger.log_error("External drive mount not found: %s" % local_path)
                return False
        else:
            remote_name = sec_info.get_remote_name()
            remote_type = sec_info.get_remote_type()
            if not sync.is_remote_configured(remote_name, remote_type):
                logger.log_error("Remote not configured: %s (%s)" % (remote_name, remote_type))
                return False

    # Check passphrase
    passphrase = primary_locker_info.get_passphrase()
    if not cryption.is_passphrase_valid(passphrase):
        logger.log_error("Invalid passphrase")
        return False
    return True

# Main sync orchestrator
def sync_lockers(
    primary_locker_type,
    secondary_locker_types,
    hash_output_dir,
    skip_hash_update = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker info objects
    primary_info = lockerinfo.LockerInfo(primary_locker_type)
    secondary_infos = [lockerinfo.LockerInfo(lt) for lt in secondary_locker_types]

    # Verify prerequisites
    if not verify_prerequisites(primary_info, secondary_infos, verbose):
        return False

    # Build authoritative hash map
    passphrase = primary_info.get_passphrase()
    primary_path = primary_info.get_remote_mount_path()
    if skip_hash_update:
        logger.log_info("Skipping hash map update (using existing)")
        authoritative_hashes = load_existing_hash_map(
            hash_output_dir = hash_output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        logger.log_info("Building authoritative hash map...")
        authoritative_hashes = build_authoritative_hash_map(
            source_path = primary_path,
            passphrase = passphrase,
            output_hash_dir = hash_output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not authoritative_hashes:
        logger.log_error("Failed to build authoritative hash map")
        return False
    logger.log_info("Found %d files in authoritative source" % len(authoritative_hashes))

    # Process each secondary
    for sec_info in secondary_infos:
        sec_name = sec_info.locker_type.val()
        exclude_patterns = sec_info.get_excluded_sync_paths()
        decrypt_on_sync = sec_info.get_decrypt_on_sync()
        if sec_info.is_local_only():
            sec_path = sec_info.get_local_path()
        else:
            sec_path = sec_info.get_remote_mount_path()
        logger.log_info("Processing secondary: %s (decrypt=%s, excludes=%d patterns)" % (
            sec_name, decrypt_on_sync, len(exclude_patterns)))

        # Build sync actions
        actions = build_sync_actions(
            authoritative_hashes = authoritative_hashes,
            secondary_path = sec_path,
            exclude_patterns = exclude_patterns,
            decrypt_on_sync = decrypt_on_sync,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not actions:
            logger.log_info("No sync actions needed for %s" % sec_name)
            continue
        logger.log_info("Found %d sync actions for %s" % (len(actions), sec_name))

        # Collapse to folders where possible
        collapsed_actions = collapse_to_folders(actions, sec_path)

        # Open editor for user review
        approved_actions = open_editor_for_sync_actions(
            actions = collapsed_actions,
            target_name = sec_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if approved_actions is None:
            logger.log_warning("Editor cancelled for %s" % sec_name)
            continue
        if not approved_actions:
            logger.log_info("No actions approved for %s" % sec_name)
            continue

        # Execute approved actions
        logger.log_info("Executing %d approved actions for %s" % (len(approved_actions), sec_name))
        success = execute_sync_actions(
            actions = approved_actions,
            source_path = primary_path,
            target_path = sec_path,
            passphrase = passphrase,
            show_progress = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Sync failed for %s" % sec_name)
            if exit_on_failure:
                return False
    return True
