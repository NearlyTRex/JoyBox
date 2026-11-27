# Imports

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import lockerinfo
from joybox import lockerbackend
from joybox import syncremotes
from joybox import editorprompt
from joybox import environment
from joybox import serialization
from joybox import hashutil
from joybox import runtime

# Recycle folder at a locker's root
RECYCLE_FOLDER = ".recycle_bin"

# Hours a cached hash map stays usable
CACHE_MAX_AGE_HOURS = 24

# Sync action types that copy a new file, and those that update an existing one
COPY_ACTION_TYPES = (config.SyncActionType.COPY, config.SyncActionType.COPY_DECRYPT, config.SyncActionType.COPY_ENCRYPT)
UPDATE_ACTION_TYPES = (config.SyncActionType.UPDATE, config.SyncActionType.UPDATE_DECRYPT, config.SyncActionType.UPDATE_ENCRYPT)
TRANSFER_ACTION_TYPES = COPY_ACTION_TYPES + UPDATE_ACTION_TYPES

# The cryption each transfer action type runs with
ACTION_CRYPTION_TYPES = {
    config.SyncActionType.COPY: config.CryptionType.NONE,
    config.SyncActionType.UPDATE: config.CryptionType.NONE,
    config.SyncActionType.COPY_DECRYPT: config.CryptionType.DECRYPT,
    config.SyncActionType.UPDATE_DECRYPT: config.CryptionType.DECRYPT,
    config.SyncActionType.COPY_ENCRYPT: config.CryptionType.ENCRYPT,
    config.SyncActionType.UPDATE_ENCRYPT: config.CryptionType.ENCRYPT
}

# What a transfer's log label adds for its cryption
CRYPTION_LABELS = {
    config.CryptionType.DECRYPT: " (decrypt)",
    config.CryptionType.ENCRYPT: " (encrypt)"
}

###########################################################
# Cache Management
###########################################################

# Folder holding cached locker hash maps, created when missing
def get_cache_dir():
    cache_dir = environment.get_cache_sync_dir()
    fileops.make_directory(src = cache_dir)
    return cache_dir

# Cache file for a locker's hash map; a map built with excludes gets its own file keyed by their MD5
def get_cache_file(locker_name, excludes = ()):

    # A map built with excludes is missing files, so it is cached apart from the full one
    if not excludes:
        return paths.join_paths(get_cache_dir(), "%s_hashmap.json" % locker_name)
    excludes_key = hashutil.calculate_string_md5("\n".join(sorted(excludes)))[:12]
    return paths.join_paths(get_cache_dir(), "%s_%s_hashmap.json" % (locker_name, excludes_key))

# Empty the hash map cache folder
def clear_cache():
    cache_dir = get_cache_dir()
    if paths.does_path_exist(cache_dir):
        fileops.remove_directory_contents(src = cache_dir)

###########################################################
# Hash Map Building
###########################################################

# Remote types that don't support server-side hashing (must use sidecar)
SIDECAR_ONLY_REMOTE_TYPES = [
    config.RemoteType.SFTP,
]

# A hash map cached less than 24 hours ago; None when absent, stale or malformed
def load_cached_hash_map(cache_file, locker_name, verbose = False):

    # Only a recent cache is used
    if not paths.is_path_file(cache_file):
        return None
    try:
        cache_mtime = paths.get_file_mod_time(cache_file)
        cache_age_hours = (runtime.get_current_timestamp() - cache_mtime) / 3600
        if cache_age_hours < 0 or cache_age_hours >= CACHE_MAX_AGE_HOURS:
            return None
    except OSError:
        return None
    hash_map = serialization.parse_json_or_none(serialization.read_text_file(cache_file))

    # A cache that does not hold a map of entries is rebuilt rather than trusted
    if not isinstance(hash_map, dict) or not all(isinstance(entry, dict) for entry in hash_map.values()):
        logger.log_warning("Ignoring unreadable hash map cache for %s" % locker_name)
        return None
    if verbose:
        logger.log_info("Using cached hash map for %s (%.1f hours old)" % (locker_name, cache_age_hours))
    return hash_map

# Whether a backend is a remote whose type holds hashes only in a sidecar
def is_sidecar_only_backend(backend):
    if not isinstance(backend, lockerbackend.RemoteBackend):
        return False
    return config.RemoteType.from_string(backend.remote_type) in SIDECAR_ONLY_REMOTE_TYPES

# List a backend's files with hashes, falling back to a remote's sidecar when its server gives none
def list_backend_hashes(backend, locker_name, excludes, verbose = False, pretend_run = False, exit_on_failure = False):
    if verbose:
        logger.log_info("Building hash map for %s..." % locker_name)
    hash_map = backend.list_files_with_hashes(
        excludes = excludes,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    lacks_hashes = bool(hash_map) and not any(entry.get("hash") for entry in hash_map.values())
    if not lacks_hashes or not isinstance(backend, lockerbackend.RemoteBackend):
        return hash_map
    if verbose:
        logger.log_info("No hashes from server, trying sidecar files for %s..." % locker_name)
    sidecar_map = backend.list_files_with_hashes_from_sidecar(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if sidecar_map is None:
        return None
    if not sidecar_map:
        return hash_map
    if verbose:
        logger.log_info("Using sidecar hashes for %s (%d files)" % (locker_name, len(sidecar_map)))
    return sidecar_map

# Get a backend's hash map: from the sidecar for remotes that hash only there, else from its listing
def get_backend_hash_map(backend, locker_name, excludes, verbose = False, pretend_run = False, exit_on_failure = False):
    if not is_sidecar_only_backend(backend):
        return list_backend_hashes(backend, locker_name, excludes, verbose, pretend_run, exit_on_failure)
    if verbose:
        remote_type = config.RemoteType.from_string(backend.remote_type)
        logger.log_info("Remote type '%s' doesn't support server-side hashing, using sidecar" % remote_type)
        logger.log_info("Building hash map from sidecar for %s..." % locker_name)
    return backend.list_files_with_hashes_from_sidecar(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Relative path to hash entry for a locker, from a recent cache or built from its backend and cached; None when the build fails
def build_locker_hash_map(
    backend,
    locker_name,
    excludes = None,
    use_cache = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Use a recent cache when there is one
    excludes = [] if excludes is None else excludes
    cache_file = get_cache_file(locker_name, excludes)
    if use_cache:
        cached_map = load_cached_hash_map(cache_file, locker_name, verbose = verbose)
        if cached_map is not None:
            return cached_map

    # Build hash map from backend
    hash_map = get_backend_hash_map(backend, locker_name, excludes, verbose, pretend_run, exit_on_failure)
    if hash_map is None:
        logger.log_error("Failed to build hash map for %s" % locker_name)
        return None

    # Save to cache. Cache even on pretend runs: the hashes are computed for real
    # (hashing is read-only), so a dry run can prime the cache for the subsequent real
    # run instead of throwing the work away.
    if hash_map:
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

# Copy or update action type for a file, with decrypt or encrypt when the two lockers' encryption differs
def get_sync_action_type(base_action, primary_encrypted, secondary_encrypted):

    # Only COPY is special-cased; anything else updates in place
    is_copy = base_action == "COPY"

    # Encrypted -> Unencrypted: DECRYPT
    if primary_encrypted and not secondary_encrypted:
        return config.SyncActionType.COPY_DECRYPT if is_copy else config.SyncActionType.UPDATE_DECRYPT

    # Unencrypted -> Encrypted: ENCRYPT
    if not primary_encrypted and secondary_encrypted:
        return config.SyncActionType.COPY_ENCRYPT if is_copy else config.SyncActionType.UPDATE_ENCRYPT

    # Same encryption state: plain copy/update
    return config.SyncActionType.COPY if is_copy else config.SyncActionType.UPDATE

# Whether a relative path is the recycle folder or inside it
def is_in_recycle_bin(rel_path):
    normalized = rel_path.replace("\\", "/")
    return normalized == RECYCLE_FOLDER or normalized.startswith(RECYCLE_FOLDER + "/")

# Whether sync leaves a path alone: excluded from writes, or in the recycle bin
def is_skipped_sync_path(rel_path, exclude_write_paths):
    return paths.matches_exclude_pattern(rel_path, exclude_write_paths) or is_in_recycle_bin(rel_path)

# Copy actions for files missing on the secondary, update actions for differing hashes, and recycle actions for secondary-only files
def build_sync_actions(
    primary_hashes,
    secondary_hashes,
    primary_encrypted = False,
    secondary_encrypted = False,
    exclude_write_paths = None):
    exclude_write_paths = [] if exclude_write_paths is None else exclude_write_paths

    # Files missing on the secondary are copied, and those whose hash differs updated
    actions = []
    for rel_path, primary_data in primary_hashes.items():
        if is_skipped_sync_path(rel_path, exclude_write_paths):
            continue
        if rel_path not in secondary_hashes:
            base_action = "COPY"
        elif primary_data.get("hash") != secondary_hashes[rel_path].get("hash"):
            base_action = "UPDATE"
        else:
            continue
        actions.append({
            "type": get_sync_action_type(base_action, primary_encrypted, secondary_encrypted),
            "src": rel_path,
            "dest": rel_path,
            "src_data": primary_data
        })

    # Files only on the secondary are orphans
    for orphan_path, orphan_data in secondary_hashes.items():
        if orphan_path in primary_hashes or is_skipped_sync_path(orphan_path, exclude_write_paths):
            continue
        actions.append({
            "type": config.SyncActionType.RECYCLE,
            "path": orphan_path,
            "src_data": orphan_data
        })
    return actions

###########################################################
# Editor Integration
###########################################################

# Get an action file's lines for actions, each its type and path
def get_action_lines(actions):
    return ["%s %s" % (action["type"].upper(), action.get("dest", action.get("src", action.get("path", "")))) for action in actions]

# Editor file text listing new, updated and (commented-out) orphan actions in sections, with instructions in its header
def generate_action_file_content(actions, target_name, include_orphans = True):

    # Group actions by type
    copy_actions = [a for a in actions if a["type"] in COPY_ACTION_TYPES]
    update_actions = [a for a in actions if a["type"] in UPDATE_ACTION_TYPES]
    recycle_actions = [a for a in actions if a["type"] == config.SyncActionType.RECYCLE]

    # Build a section for each group, orphans commented out so they are kept by default
    sections = []
    if copy_actions:
        sections.append({"title": "NEW FILES (%d)" % len(copy_actions), "items": get_action_lines(copy_actions)})
    if update_actions:
        sections.append({"title": "UPDATED FILES (%d)" % len(update_actions), "items": get_action_lines(update_actions)})
    if include_orphans and recycle_actions:
        sections.append({
            "title": "ORPHAN FILES - will be moved to .recycle_bin (%d)" % len(recycle_actions),
            "description": "Uncomment to recycle, leave commented to keep",
            "items": get_action_lines(recycle_actions),
            "commented": True
        })
    return editorprompt.generate_action_file(
        sections = sections,
        header_lines = [
            "%s Sync Actions" % target_name,
            "Lines starting with # are ignored",
            "Delete lines or comment them out to skip actions",
            "Save and close editor to proceed, or delete all lines to abort"
        ])

# The proposed actions the edited lines still name, by type and path, taking any destination the edit gave; unknown lines are warned about and dropped
def match_edited_actions(actions, edited_lines):

    # Index the proposed actions by type and path
    proposed = {}
    for action in actions:
        action_type = normalize_action_type(action)
        if action_type == config.SyncActionType.RECYCLE:
            path = action.get("path", "")
        else:
            path = action.get("src", "")
        proposed[(action_type, path)] = action

    # Keep the proposed actions the edited lines still name, taking any new destination
    approved = []
    for line in edited_lines:
        action_type = normalize_action_type(line)
        path = line.get("src", line.get("path", ""))
        action = proposed.get((action_type, path))
        if action is None:
            logger.log_warning("Ignoring an action that was not proposed: %s %s" % (line.get("type", ""), path))
            continue
        approved_action = dict(action)
        if "dest" in line and action_type != config.SyncActionType.RECYCLE:
            approved_action["dest"] = line["dest"]
        approved.append(approved_action)
    return approved

# Let the user edit the proposed actions in an editor; returns the approved ones, or None when cancelled
def open_editor_for_sync_actions(
    actions,
    target_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    content = generate_action_file_content(actions, target_name)
    edited_lines = editorprompt.open_editor_for_actions(
        content = content,
        prefix = "locker_sync_",
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if edited_lines is None:
        return None
    return match_edited_actions(actions, edited_lines)

###########################################################
# Action Execution
###########################################################

# Recycle a recycle action's path on a backend, returning whether it succeeded
def recycle_action_path(action, backend, verbose = False, pretend_run = False, exit_on_failure = False):
    path = action.get("path", "")
    if verbose:
        logger.log_info("Recycling: %s" % path)
    return backend.recycle_file(
        rel_path = path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Get the log label for a transfer action type: copying or updating, and any cryption
def get_transfer_label(action_type):
    label = "Copying" if action_type in COPY_ACTION_TYPES else "Updating"
    return label + CRYPTION_LABELS.get(ACTION_CRYPTION_TYPES[action_type], "")

# Run a transfer or recycle action from the primary onto a secondary, returning whether it succeeded
def execute_sync_action(
    action,
    primary_backend,
    secondary_backend,
    passphrase = None,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    action_type = normalize_action_type(action)
    if action_type == config.SyncActionType.RECYCLE:
        return recycle_action_path(action, secondary_backend, verbose, pretend_run, exit_on_failure)
    src_path = action.get("src", "")
    dest_path = action.get("dest", src_path)
    if verbose:
        logger.log_info("%s: %s -> %s" % (get_transfer_label(action_type), src_path, dest_path))
    return secondary_backend.sync_from(
        src_backend = primary_backend,
        src_rel_path = src_path,
        dest_rel_path = dest_path,
        cryption_type = ACTION_CRYPTION_TYPES[action_type],
        passphrase = passphrase,
        show_progress = show_progress,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Run transfer and recycle actions one at a time, logging the tally; True when none failed
def execute_sync_actions(
    actions,
    primary_backend,
    secondary_backend,
    passphrase = None,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Run each transfer and recycle action, passing over any other type
    success_count = 0
    fail_count = 0
    for action in actions:
        action_type = normalize_action_type(action)
        if action_type != config.SyncActionType.RECYCLE and action_type not in ACTION_CRYPTION_TYPES:
            continue
        if execute_sync_action(
            action, primary_backend, secondary_backend, passphrase, show_progress, verbose, pretend_run, exit_on_failure):
            success_count += 1
        else:
            fail_count += 1
    logger.log_info("Sync complete: %d succeeded, %d failed" % (success_count, fail_count))
    return fail_count == 0

# An action's type as a SyncActionType, parsing it when given as a string
def normalize_action_type(action):
    raw_type = action.get("type", "")
    if isinstance(raw_type, str):
        return config.SyncActionType.from_string(raw_type)
    return raw_type

# Group transfer actions by the cryption they run with, so each group can be one transfer
def group_actions_by_cryption(actions):
    groups = {cryption_type: [] for cryption_type in (config.CryptionType.NONE, config.CryptionType.ENCRYPT, config.CryptionType.DECRYPT)}
    for action in actions:
        cryption_type = ACTION_CRYPTION_TYPES.get(normalize_action_type(action))
        if cryption_type is not None:
            groups[cryption_type].append(action)
    return groups

# One batched transfer per cryption type, then recycles one by one; returns whether all succeeded and the paths that did
def execute_sync_actions_batched(
    actions,
    primary_backend,
    secondary_backend,
    passphrase = None,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Run each cryption type's transfers as a single batched transfer
    succeeded_paths = []
    failed_paths = []
    for cryption_type, group in group_actions_by_cryption(actions).items():
        if not group:
            continue
        ok_paths, fail_paths = secondary_backend.sync_batch_from(
            src_backend = primary_backend,
            actions = group,
            cryption_type = cryption_type,
            passphrase = passphrase,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        succeeded_paths.extend(ok_paths)
        failed_paths.extend(fail_paths)

    # Handle recycle actions individually (rare; additive backups skip these)
    for action in actions:
        if normalize_action_type(action) == config.SyncActionType.RECYCLE:
            recycled = recycle_action_path(action, secondary_backend, verbose, pretend_run, exit_on_failure)
            (succeeded_paths if recycled else failed_paths).append(action.get("path", ""))
    logger.log_info("Sync complete: %d succeeded, %d failed" % (len(succeeded_paths), len(failed_paths)))
    return (len(failed_paths) == 0, succeeded_paths)

###########################################################
# Main Sync Orchestrator
###########################################################

# Check a backend can be synced: a local one's path exists, or a remote one is configured
def is_backend_accessible(backend, role):
    if isinstance(backend, lockerbackend.LocalBackend):
        root_path = backend.get_root_path()
        if not root_path or not paths.does_path_exist(root_path):
            logger.log_error("%s locker path not accessible: %s" % (role, root_path))
            return False
    elif isinstance(backend, lockerbackend.RemoteBackend):
        if not syncremotes.is_remote_configured(backend.remote_name, backend.remote_type):
            logger.log_error("%s remote not configured: %s" % (role, backend.remote_name))
            return False
    return True

# Whether the primary and every secondary locker is reachable: local paths exist, remotes are configured
def verify_prerequisites(
    primary_backend,
    secondary_backends):
    if not is_backend_accessible(primary_backend, "Primary"):
        return False
    return all(is_backend_accessible(sec_backend, "Secondary") for sec_backend in secondary_backends)

# Build the primary's hash map, or None. An empty primary would make every secondary
# file an orphan, so it is refused rather than synced.
def build_primary_hash_map(primary_info, primary_backend, skip_cache = False, verbose = False, pretend_run = False, exit_on_failure = False):
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
    if primary_hashes is None:
        logger.log_error("Failed to build primary hash map")
        return None
    if not primary_hashes:
        logger.log_error("Primary locker %s holds no files, refusing to sync from it" % primary_name)
        return None
    logger.log_info("Primary hash map: %d files" % len(primary_hashes))
    return primary_hashes

# Build a secondary's hash map, leaving out its excludes, or None
def build_secondary_hash_map(sec_name, sec_backend, sec_excludes, skip_cache = False, verbose = False, pretend_run = False, exit_on_failure = False):
    secondary_hashes = build_locker_hash_map(
        backend = sec_backend,
        locker_name = sec_name,
        excludes = sec_excludes,
        use_cache = not skip_cache,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if secondary_hashes is None:
        logger.log_error("Failed to build secondary hash map for %s" % sec_name)
        return None
    logger.log_info("Secondary hash map for %s: %d files" % (sec_name, len(secondary_hashes)))
    return secondary_hashes

# Approve sync actions: through the editor when interactive, else the transfers, and the
# recycles too when recycling orphans. A cancelled editor approves none.
def approve_sync_actions(actions, sec_name, interactive = True, recycle_orphans = False, verbose = False, pretend_run = False, exit_on_failure = False):
    if interactive:
        approved_actions = open_editor_for_sync_actions(
            actions = actions,
            target_name = sec_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if approved_actions is None:
            logger.log_warning("Editor cancelled for %s" % sec_name)
            return []
    else:
        approved_actions = [a for a in actions if a["type"] in TRANSFER_ACTION_TYPES]
        if recycle_orphans:
            approved_actions += [a for a in actions if a["type"] == config.SyncActionType.RECYCLE]
    if not approved_actions:
        logger.log_info("No actions approved for %s" % sec_name)
    return approved_actions

# Get the passphrase a sync between lockers uses: the primary's to decrypt, the secondary's to encrypt, else none
def get_sync_passphrase(primary_info, sec_info):
    if primary_info.is_encrypted() and not sec_info.is_encrypted():
        return primary_info.get_passphrase()
    if not primary_info.is_encrypted() and sec_info.is_encrypted():
        return sec_info.get_passphrase()
    return None

# Update a secondary's cached hash map to reflect what was just moved, so a re-run within the
# cache window does not re-detect the same files: uploaded files now match the primary, and
# recycled ones and renamed uploads, which match no primary entry of their name, are dropped
def update_cached_secondary_hashes(secondary_hashes, primary_hashes, succeeded, approved_actions, cache_file, verbose = False):
    recycled_paths = set(
        a.get("path", "") for a in approved_actions
        if normalize_action_type(a) == config.SyncActionType.RECYCLE)
    renamed_paths = set(
        a.get("dest", "") for a in approved_actions
        if a.get("dest", a.get("src", "")) != a.get("src", ""))
    updated = 0
    for rel in succeeded:
        if rel in recycled_paths or rel in renamed_paths:
            if secondary_hashes.pop(rel, None) is not None:
                updated += 1
        elif rel in primary_hashes:
            secondary_hashes[rel] = primary_hashes[rel]
            updated += 1
    if updated:
        serialization.write_json_file(
            src = cache_file,
            json_data = secondary_hashes,
            verbose = verbose)

# Refresh a secondary's hash sidecar once, from authoritative local content: only when the
# primary is local (correct plaintext) and the secondary a remote that hashes only in a
# sidecar (e.g. SFTP). Returns whether the refresh, when there was one, succeeded.
def refresh_secondary_sidecar(primary_backend, sec_backend, sec_name, excludes, verbose = False, pretend_run = False, exit_on_failure = False):
    if not isinstance(primary_backend, lockerbackend.LocalBackend) or not is_sidecar_only_backend(sec_backend):
        return True
    logger.log_info("Refreshing hash sidecar for %s..." % sec_name)
    if sec_backend.update_sidecar_from_local(
        local_root_path = primary_backend.get_root_path(),
        excludes = excludes,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):
        return True
    logger.log_error("Failed to refresh hash sidecar for %s" % sec_name)
    return False

# Plan a sync onto a secondary: the actions its hash map differs from the primary's by, as approved
def plan_secondary_sync(primary_info, primary_hashes, sec_info, secondary_hashes, interactive = True, recycle_orphans = False, verbose = False, pretend_run = False, exit_on_failure = False):
    sec_name = sec_info.get_locker_name()
    actions = build_sync_actions(
        primary_hashes = primary_hashes,
        secondary_hashes = secondary_hashes,
        primary_encrypted = primary_info.is_encrypted(),
        secondary_encrypted = sec_info.is_encrypted(),
        exclude_write_paths = sec_info.get_excluded_dirs())
    if not actions:
        logger.log_info("No sync actions needed for %s" % sec_name)
        return []
    logger.log_info("Found %d sync actions for %s" % (len(actions), sec_name))
    return approve_sync_actions(actions, sec_name, interactive, recycle_orphans, verbose, pretend_run, exit_on_failure)

# Sync the primary onto one secondary, returning whether every step held. A failed transfer
# leaves the sidecar alone, so the next run re-detects and retries the missing files.
def sync_secondary(primary, sec_info, sec_backend, skip_cache = False, interactive = True, recycle_orphans = False, rebuild_sidecars = True, verbose = False, pretend_run = False, exit_on_failure = False):
    primary_info, primary_backend, primary_hashes = primary
    sec_name = sec_info.get_locker_name()
    exclude_patterns = sec_info.get_excluded_dirs()
    sec_excludes = exclude_patterns + [RECYCLE_FOLDER + "/**"]
    logger.log_info("Processing secondary: %s (excludes=%d patterns)" % (sec_name, len(exclude_patterns)))
    secondary_hashes = build_secondary_hash_map(sec_name, sec_backend, sec_excludes, skip_cache, verbose, pretend_run, exit_on_failure)
    if secondary_hashes is None:
        return False
    approved_actions = plan_secondary_sync(
        primary_info, primary_hashes, sec_info, secondary_hashes, interactive, recycle_orphans, verbose, pretend_run, exit_on_failure)
    if not approved_actions:
        return True

    # Execute approved actions (batched - one transfer per cryption group)
    logger.log_info("Executing %d approved actions for %s" % (len(approved_actions), sec_name))
    success, succeeded = execute_sync_actions_batched(
        actions = approved_actions,
        primary_backend = primary_backend,
        secondary_backend = sec_backend,
        passphrase = get_sync_passphrase(primary_info, sec_info),
        show_progress = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Sync failed for %s" % sec_name)
        if exit_on_failure:
            return False
    if succeeded and not pretend_run:
        update_cached_secondary_hashes(
            secondary_hashes, primary_hashes, succeeded, approved_actions, get_cache_file(sec_name, sec_excludes), verbose)
    if rebuild_sidecars and success:
        return refresh_secondary_sidecar(primary_backend, sec_backend, sec_name, exclude_patterns, verbose, pretend_run, exit_on_failure)
    return success

# Sync a primary locker onto each secondary by hash comparison, with editor approval when interactive; True when every secondary synced
def sync_lockers(
    primary_locker_type,
    secondary_locker_types,
    skip_cache = False,
    interactive = True,
    recycle_orphans = False,
    rebuild_sidecars = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker info objects and their backends
    primary_info = lockerinfo.LockerInfo(primary_locker_type)
    secondary_infos = [lockerinfo.LockerInfo(lt) for lt in secondary_locker_types]
    primary_backend = lockerbackend.get_backend_for_locker(primary_info)
    secondary_backends = [lockerbackend.get_backend_for_locker(info) for info in secondary_infos]
    if not verify_prerequisites(primary_backend, secondary_backends):
        return False
    primary_hashes = build_primary_hash_map(primary_info, primary_backend, skip_cache, verbose, pretend_run, exit_on_failure)
    if not primary_hashes:
        return False

    # Sync onto each secondary, stopping at the first failure when told to
    all_success = True
    for sec_info, sec_backend in zip(secondary_infos, secondary_backends, strict = True):
        if not sync_secondary(
            (primary_info, primary_backend, primary_hashes), sec_info, sec_backend,
            skip_cache, interactive, recycle_orphans, rebuild_sidecars, verbose, pretend_run, exit_on_failure):
            all_success = False
            if exit_on_failure:
                return False
    return all_success

###########################################################

# The locker types named in a comma-separated list, quitting on an unknown name or when none is named
def parse_locker_types(locker_names):
    locker_types = []
    for locker_str in locker_names.split(","):
        locker_str = locker_str.strip()
        if not locker_str:
            continue
        locker_type = config.LockerType.from_string(locker_str)
        if locker_type:
            locker_types.append(locker_type)
        else:
            logger.log_error("Unknown locker type: %s" % locker_str, quit_program = True)
    if not locker_types:
        logger.log_error("No valid secondary locker types specified", quit_program = True)
    return locker_types

# Sync the primary locker to each secondary named in the comma-separated list, clearing the
# hash map cache first when asked; False, logged, when the sync fails
def run_locker_sync(primary_locker_type, secondary_locker_names, skip_cache = False, clear_hash_cache = False, verbose = False, pretend_run = False, exit_on_failure = False):
    secondary_locker_types = parse_locker_types(secondary_locker_names)
    if clear_hash_cache:
        logger.log_info("Clearing hash map cache...")
        clear_cache()
    logger.log_info("Primary locker: %s" % primary_locker_type)
    logger.log_info("Secondary lockers: %s" % ", ".join([lt.val() for lt in secondary_locker_types]))
    success = sync_lockers(
        primary_locker_type = primary_locker_type,
        secondary_locker_types = secondary_locker_types,
        skip_cache = skip_cache,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if success:
        logger.log_info("Locker sync completed successfully")
    else:
        logger.log_error("Locker sync failed")
    return success
