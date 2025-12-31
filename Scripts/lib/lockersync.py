# Imports
import os
import os.path
import sys
import fnmatch

# Local imports
import config
import system
import logger
import paths
import fileops
import hashing
import cryption
import lockerinfo
import lockerbackend
import sync
import editorprompt
import environment
import serialization

###########################################################
# Cache Management
###########################################################

def get_cache_dir():
    cache_root = environment.get_cache_root_dir()
    cache_dir = paths.join_paths(cache_root, "lockersync")
    fileops.make_directory(src = cache_dir)
    return cache_dir

def get_cache_file(locker_name):
    return paths.join_paths(get_cache_dir(), "%s_hashmap.json" % locker_name)

def clear_cache():
    cache_dir = get_cache_dir()
    if paths.does_path_exist(cache_dir):
        fileops.remove_directory_contents(src = cache_dir)

###########################################################
# Hash Map Building
###########################################################

def build_locker_hash_map(
    backend,
    locker_name,
    excludes = [],
    use_cache = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if cache exists and is recent
    cache_file = get_cache_file(locker_name)
    if use_cache and paths.is_path_file(cache_file):
        try:
            cache_mtime = paths.get_file_mod_time(cache_file)
            cache_age_hours = (environment.get_current_timestamp() - cache_mtime) / 3600
            if cache_age_hours < 24:  # Use cache if less than 24 hours old
                if verbose:
                    logger.log_info("Using cached hash map for %s (%.1f hours old)" % (locker_name, cache_age_hours))
                return serialization.read_json_file(src = cache_file)
        except:
            pass

    # Build hash map from backend
    if verbose:
        logger.log_info("Building hash map for %s..." % locker_name)
    hash_map = backend.list_files_with_hashes(
        excludes = excludes,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Save to cache
    if hash_map and not pretend_run:
        serialization.write_json_file(
            src = cache_file,
            json_data = hash_map,
            verbose = verbose)
    if verbose:
        logger.log_info("Hash map for %s: %d files" % (locker_name, len(hash_map)))
    return hash_map

###########################################################
# Sync Actions
###########################################################

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

def get_sync_action_type(base_action, primary_encrypted, secondary_encrypted):

    # Determine the correct action type based on encryption states
    if primary_encrypted and not secondary_encrypted:

        # Encrypted -> Unencrypted: DECRYPT
        if base_action == "COPY":
            return config.SyncActionType.COPY_DECRYPT
        elif base_action == "UPDATE":
            return config.SyncActionType.UPDATE_DECRYPT
    elif not primary_encrypted and secondary_encrypted:

        # Unencrypted -> Encrypted: ENCRYPT
        if base_action == "COPY":
            return config.SyncActionType.COPY_ENCRYPT
        elif base_action == "UPDATE":
            return config.SyncActionType.UPDATE_ENCRYPT

    # Same encryption state: plain copy/update
    if base_action == "COPY":
        return config.SyncActionType.COPY
    return config.SyncActionType.UPDATE

def build_sync_actions(
    primary_hashes,
    secondary_hashes,
    primary_encrypted = False,
    secondary_encrypted = False,
    exclude_write_paths = [],
    verbose = False):

    # Process each file in primary
    actions = []
    secondary_paths = set(secondary_hashes.keys())
    for rel_path, primary_data in primary_hashes.items():

        # Skip excluded paths
        if matches_exclude_pattern(rel_path, exclude_write_paths):
            continue

        # Add action
        if rel_path in secondary_hashes:

            # File exists on both - check if hash matches
            secondary_data = secondary_hashes[rel_path]
            if primary_data.get("hash") != secondary_data.get("hash"):
                action_type = get_sync_action_type("UPDATE", primary_encrypted, secondary_encrypted)
                actions.append({
                    "type": action_type,
                    "src": rel_path,
                    "dest": rel_path,
                    "src_data": primary_data
                })
            secondary_paths.discard(rel_path)
        else:

            # File missing on secondary - needs copy
            action_type = get_sync_action_type("COPY", primary_encrypted, secondary_encrypted)
            actions.append({
                "type": action_type,
                "src": rel_path,
                "dest": rel_path,
                "src_data": primary_data
            })

    # Remaining files in secondary are orphans (not in primary)
    for orphan_path in secondary_paths:
        if matches_exclude_pattern(orphan_path, exclude_write_paths):
            continue
        if orphan_path.startswith(".recycle_bin"):
            continue
        actions.append({
            "type": config.SyncActionType.RECYCLE,
            "path": orphan_path,
            "src_data": secondary_hashes.get(orphan_path)
        })
    return actions

###########################################################
# Editor Integration
###########################################################

def generate_action_file_content(actions, target_name, include_orphans = True):

    # Group actions by type
    copy_types = (config.SyncActionType.COPY, config.SyncActionType.COPY_DECRYPT, config.SyncActionType.COPY_ENCRYPT)
    update_types = (config.SyncActionType.UPDATE, config.SyncActionType.UPDATE_DECRYPT, config.SyncActionType.UPDATE_ENCRYPT)
    copy_actions = [a for a in actions if a["type"] in copy_types]
    update_actions = [a for a in actions if a["type"] in update_types]
    recycle_actions = [a for a in actions if a["type"] == config.SyncActionType.RECYCLE]

    # Build sections
    sections = []

    # New files section
    if copy_actions:
        items = []
        for action in copy_actions:
            path = action.get("dest", action.get("src", ""))
            action_type = action["type"]
            items.append("%s %s" % (action_type.upper(), path))
        sections.append({
            "title": "NEW FILES (%d)" % len(copy_actions),
            "items": items
        })

    # Updated files section
    if update_actions:
        items = []
        for action in update_actions:
            path = action.get("dest", action.get("src", ""))
            action_type = action["type"]
            items.append("%s %s" % (action_type.upper(), path))
        sections.append({
            "title": "UPDATED FILES (%d)" % len(update_actions),
            "items": items
        })

    # Orphan files section (commented out by default - will be recycled)
    if include_orphans and recycle_actions:
        items = []
        for action in recycle_actions:
            path = action.get("path", "")
            items.append("%s %s" % (config.SyncActionType.RECYCLE.upper(), path))
        sections.append({
            "title": "ORPHAN FILES - will be moved to .recycle_bin (%d)" % len(recycle_actions),
            "description": "Uncomment to recycle, leave commented to keep",
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

###########################################################
# Action Execution
###########################################################

def execute_sync_actions(
    actions,
    primary_backend,
    secondary_backend,
    passphrase = None,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Define action type groups
    copy_types = (config.SyncActionType.COPY, config.SyncActionType.COPY_DECRYPT, config.SyncActionType.COPY_ENCRYPT)
    update_types = (config.SyncActionType.UPDATE, config.SyncActionType.UPDATE_DECRYPT, config.SyncActionType.UPDATE_ENCRYPT)
    decrypt_types = (config.SyncActionType.COPY_DECRYPT, config.SyncActionType.UPDATE_DECRYPT)
    encrypt_types = (config.SyncActionType.COPY_ENCRYPT, config.SyncActionType.UPDATE_ENCRYPT)

    # Run sync actions
    success_count = 0
    fail_count = 0
    for action in actions:

        # Normalize action type
        raw_type = action.get("type", "")
        if isinstance(raw_type, str):
            action_type = config.SyncActionType.from_string(raw_type)
        else:
            action_type = raw_type

        # Handle COPY and UPDATE actions (including encrypt/decrypt variants)
        if action_type in copy_types or action_type in update_types:
            src_path = action.get("src", "")
            dest_path = action.get("dest", src_path)
            action_label = "Copying" if action_type in copy_types else "Updating"
            if action_type in decrypt_types:
                action_label += " (decrypt)"
            elif action_type in encrypt_types:
                action_label += " (encrypt)"
            if verbose:
                logger.log_info("%s: %s -> %s" % (action_label, src_path, dest_path))

            # Determine cryption type
            cryption_type = config.CryptionType.NONE
            if action_type in decrypt_types:
                cryption_type = config.CryptionType.DECRYPT
            elif action_type in encrypt_types:
                cryption_type = config.CryptionType.ENCRYPT

            success = secondary_backend.copy_file_from(
                src_backend = primary_backend,
                src_rel_path = src_path,
                dest_rel_path = dest_path,
                cryption_type = cryption_type,
                passphrase = passphrase,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if success:
                success_count += 1
            else:
                fail_count += 1

        # Handle RECYCLE action
        elif action_type == config.SyncActionType.RECYCLE:
            path = action.get("path", "")
            if verbose:
                logger.log_info("Recycling: %s" % path)
            success = secondary_backend.recycle_file(
                rel_path = path,
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

###########################################################
# Main Sync Orchestrator
###########################################################

def verify_prerequisites(
    primary_backend,
    secondary_backends,
    verbose = False):

    # Check primary
    primary_path = primary_backend.get_root_path()
    if isinstance(primary_backend, lockerbackend.LocalBackend):
        if not primary_path or not paths.does_path_exist(primary_path):
            logger.log_error("Primary locker path not accessible: %s" % primary_path)
            return False
    elif isinstance(primary_backend, lockerbackend.RemoteBackend):
        if not sync.is_remote_configured(primary_backend.remote_name, primary_backend.remote_type):
            logger.log_error("Primary remote not configured: %s" % primary_backend.remote_name)
            return False

    # Check each secondary
    for sec_backend in secondary_backends:
        if isinstance(sec_backend, lockerbackend.LocalBackend):
            sec_path = sec_backend.get_root_path()
            if not sec_path or not paths.does_path_exist(sec_path):
                logger.log_error("Secondary locker path not accessible: %s" % sec_path)
                return False
        elif isinstance(sec_backend, lockerbackend.RemoteBackend):
            if not sync.is_remote_configured(sec_backend.remote_name, sec_backend.remote_type):
                logger.log_error("Secondary remote not configured: %s" % sec_backend.remote_name)
                return False
    return True

def sync_lockers(
    primary_locker_type,
    secondary_locker_types,
    skip_cache = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker info objects
    primary_info = lockerinfo.LockerInfo(primary_locker_type)
    secondary_infos = [lockerinfo.LockerInfo(lt) for lt in secondary_locker_types]

    # Create backends
    primary_backend = lockerbackend.get_backend_for_locker(primary_info)
    secondary_backends = [lockerbackend.get_backend_for_locker(info) for info in secondary_infos]

    # Verify prerequisites
    if not verify_prerequisites(primary_backend, secondary_backends, verbose):
        return False

    # Build primary hash map
    primary_name = primary_info.get_locker_name()
    logger.log_info("Building primary hash map from %s..." % primary_name)
    primary_hashes = build_locker_hash_map(
        backend = primary_backend,
        locker_name = primary_name,
        excludes = [],
        use_cache = not skip_cache,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not primary_hashes:
        logger.log_error("Failed to build primary hash map")
        return False
    logger.log_info("Primary hash map: %d files" % len(primary_hashes))

    # Process each secondary
    for sec_info, sec_backend in zip(secondary_infos, secondary_backends):
        sec_name = sec_info.get_locker_name()
        exclude_patterns = sec_info.get_excluded_sync_paths()
        logger.log_info("Processing secondary: %s (excludes=%d patterns)" % (
            sec_name, len(exclude_patterns)))

        # Build secondary hash map
        secondary_hashes = build_locker_hash_map(
            backend = sec_backend,
            locker_name = sec_name,
            excludes = exclude_patterns + [".recycle_bin/**"],  # Always exclude recycle bin
            use_cache = not skip_cache,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if secondary_hashes is None:
            logger.log_error("Failed to build secondary hash map for %s" % sec_name)
            if exit_on_failure:
                return False
            continue
        logger.log_info("Secondary hash map for %s: %d files" % (sec_name, len(secondary_hashes)))

        # Build sync actions
        actions = build_sync_actions(
            primary_hashes = primary_hashes,
            secondary_hashes = secondary_hashes,
            primary_encrypted = primary_info.is_encrypted(),
            secondary_encrypted = sec_info.is_encrypted(),
            exclude_write_paths = exclude_patterns,
            verbose = verbose)
        if not actions:
            logger.log_info("No sync actions needed for %s" % sec_name)
            continue
        logger.log_info("Found %d sync actions for %s" % (len(actions), sec_name))

        # Open editor for user review
        approved_actions = open_editor_for_sync_actions(
            actions = actions,
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

        # Determine passphrase based on encryption direction
        # Decrypt: use primary's passphrase, Encrypt: use secondary's passphrase
        if primary_info.is_encrypted() and not sec_info.is_encrypted():
            passphrase = primary_info.get_passphrase()
        elif not primary_info.is_encrypted() and sec_info.is_encrypted():
            passphrase = sec_info.get_passphrase()
        else:
            passphrase = None

        # Execute approved actions
        logger.log_info("Executing %d approved actions for %s" % (len(approved_actions), sec_name))
        success = execute_sync_actions(
            actions = approved_actions,
            primary_backend = primary_backend,
            secondary_backend = sec_backend,
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
