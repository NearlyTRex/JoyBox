# Imports
import config
import logger
import lockerinfo
import lockersync

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
