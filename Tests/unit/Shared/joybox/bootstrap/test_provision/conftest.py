# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import serverinfo
from joybox.bootstrap import provision

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted:
# in front, this directory's own conftest would shadow the suite's top level
# one for everything that imports it by name.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)

SECTION = serverinfo.SECTION


@pytest.fixture
def entry(isolated_settings):
    values = {
        "server_1_host": "192.168.122.10",
        "server_1_user": "deploy",
        "server_1_key_filepath": "/home/deploy/.ssh/id_ed25519",
        "server_1_domain_name": "example.com",
        "server_1_htpasswd_pass": "admin-secret",
    }
    for field, value in values.items():
        isolated_settings.set_value(SECTION, field, value)
    return isolated_settings


@pytest.fixture
def guest(entry, monkeypatch):
    entry.set_value(SECTION, "server_1_vm", "joybox-test")
    vm = provision.virtualmachine
    log = []
    monkeypatch.setattr(vm, "does_vm_exist", lambda *a, **k: True)
    monkeypatch.setattr(vm, "get_vm_interface_mac", lambda name, **k: vm.get_vm_mac(name))
    monkeypatch.setattr(vm, "reserve_address", lambda name, address, **k: log.append(("reserve", address)) or True)
    monkeypatch.setattr(vm, "start_vm", lambda name, **k: log.append(("start", name)) or True)
    monkeypatch.setattr(vm, "create_vm", lambda **kwargs: log.append(("create", kwargs)) or True)
    monkeypatch.setattr(vm, "snapshot_vm", lambda name, snapshot, **k: log.append(("snapshot", snapshot)) or True)
    monkeypatch.setattr(vm, "delete_snapshot", lambda name, snapshot, **k: log.append(("unsnapshot", snapshot)) or True)
    monkeypatch.setattr(vm, "revert_vm", lambda name, snapshot, **k: log.append(("revert", snapshot)) or True)
    monkeypatch.setattr(provision.hostsfile, "set_entries", lambda **kwargs: log.append(("hosts", kwargs)) or True)
    monkeypatch.setattr(provision.time, "sleep", lambda seconds: None)
    return log
