# Imports
from joybox import config
from joybox import logger
from joybox import lockerinfo
from joybox import lockersync
from joybox import runtime

###########################################################
# Master Backup Orchestrator
###########################################################

# Run a master backup: the local locker is the authoritative source, and each remote
# locker is an additive backup destination. Delegates to the locker sync orchestrator
# (run non-interactively) which also refreshes remote hash sidecars where needed.
def run_master_backup(
    local_locker_type = config.LockerType.LOCAL,
    remote_locker_types = None,
    rebuild_sidecars = True,
    recycle_orphans = False,
    skip_cache = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Default destinations
    if remote_locker_types is None:
        remote_locker_types = [config.LockerType.HETZNER, config.LockerType.GDRIVE]
    remote_locker_types = list(remote_locker_types)

    # Log the plan
    local_name = lockerinfo.LockerInfo(local_locker_type).get_locker_name()
    dest_names = ", ".join([lockerinfo.LockerInfo(lt).get_locker_name() for lt in remote_locker_types])
    logger.log_info("Master backup: %s (authoritative source) -> %s" % (local_name, dest_names))
    logger.log_info("Mode: %s" % ("mirror (recycle orphans)" if recycle_orphans else "additive (keep remote copies)"))

    # Delegate to the locker sync orchestrator (non-interactive, additive by default).
    # Excludes are applied per-destination inside sync_lockers, and the single
    # post-sync sidecar refresh runs there too (once per destination that needs one).
    return lockersync.sync_lockers(
        primary_locker_type = local_locker_type,
        secondary_locker_types = remote_locker_types,
        skip_cache = skip_cache,
        interactive = False,
        recycle_orphans = recycle_orphans,
        rebuild_sidecars = rebuild_sidecars,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################
# Master Backup Command
###########################################################

# The locker types a comma-separated list names, skipping blank entries; quits on an
# unknown name or when the list names none
def parse_remote_locker_types(remote_lockers):
    remote_locker_types = []
    for locker_str in remote_lockers.split(","):
        locker_str = locker_str.strip()
        if not locker_str:
            continue
        locker_type = config.LockerType.from_string(locker_str)
        if locker_type:
            remote_locker_types.append(locker_type)
        else:
            logger.log_error("Unknown locker type: %s" % locker_str, quit_program = True)
    if not remote_locker_types:
        logger.log_error("No valid remote locker types specified", quit_program = True)
    return remote_locker_types

# Preview lines for a master backup: its source, destinations, orphan handling and phases
def get_master_backup_preview(local_locker_type, remote_locker_types, recycle_orphans = False, rebuild_sidecars = True):
    local_name = lockerinfo.LockerInfo(local_locker_type).get_locker_name()
    details = [
        "Source (authoritative): %s" % local_name,
        "Destinations: %s" % ", ".join([lt.val() for lt in remote_locker_types]),
        "Orphan handling: %s" % ("recycle to .recycle_bin" if recycle_orphans else "keep (additive only)"),
        "Rebuild hash sidecars: %s" % ("Yes" if rebuild_sidecars else "No"),
        "Phase 1: hash source + each destination, compute differences",
        "Phase 2: upload new/changed files to each destination",
    ]
    if rebuild_sidecars:
        details.append("Phase 3: refresh remote hash sidecars (e.g. Hetzner)")
    return details

# Run a master backup and log its outcome; quits with status 1 when it fails
def run_master_backup_or_quit(
    local_locker_type,
    remote_locker_types,
    rebuild_sidecars = True,
    recycle_orphans = False,
    skip_cache = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    success = run_master_backup(
        local_locker_type = local_locker_type,
        remote_locker_types = remote_locker_types,
        rebuild_sidecars = rebuild_sidecars,
        recycle_orphans = recycle_orphans,
        skip_cache = skip_cache,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if success:
        logger.log_info("Master backup completed successfully")
    else:
        logger.log_error("Master backup failed")
        runtime.quit_program(1)
