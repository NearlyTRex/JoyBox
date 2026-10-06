# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import lockerinfo
from joybox import lockersync
from joybox import masterbackup


###########################################################
# Master backup
#
# The local locker is the authoritative source; every remote is an additive
# destination, synced without prompting.
###########################################################

class NamedLocker:
    def __init__(self, locker_type):
        self.locker_type = locker_type

    def get_locker_name(self):
        return str(self.locker_type)


@pytest.fixture
def sync_calls(monkeypatch):
    calls = []

    def sync_lockers(**kwargs):
        calls.append(kwargs)
        return True

    monkeypatch.setattr(lockerinfo, "LockerInfo", NamedLocker)
    monkeypatch.setattr(lockersync, "sync_lockers", sync_lockers)
    return calls


def test_the_default_destinations_are_hetzner_and_gdrive(sync_calls):
    assert masterbackup.run_master_backup() is True

    call = sync_calls[0]
    assert call["primary_locker_type"] == config.LockerType.LOCAL
    assert call["secondary_locker_types"] == [config.LockerType.HETZNER, config.LockerType.GDRIVE]


def test_a_master_backup_never_prompts_and_keeps_remote_copies_by_default(sync_calls):
    masterbackup.run_master_backup()

    assert sync_calls[0]["interactive"] is False
    assert sync_calls[0]["recycle_orphans"] is False
    assert sync_calls[0]["rebuild_sidecars"] is True


def test_explicit_destinations_and_mirror_mode_pass_through(sync_calls):
    masterbackup.run_master_backup(
        remote_locker_types = (config.LockerType.GDRIVE,),
        recycle_orphans = True,
        skip_cache = True,
        pretend_run = True)

    call = sync_calls[0]
    assert call["secondary_locker_types"] == [config.LockerType.GDRIVE]
    assert call["recycle_orphans"] is True
    assert call["skip_cache"] is True
    assert call["pretend_run"] is True
