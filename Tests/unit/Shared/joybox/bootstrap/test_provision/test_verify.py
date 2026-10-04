# Imports
import pytest

# Local imports
from joybox.bootstrap import provision
from provision_helpers import World, build


###########################################################
# Verify
###########################################################

def test_verification_runs_as_the_account(entry, monkeypatch):
    world = World({"deploy": True, "root": False})
    seen = []
    monkeypatch.setattr(provision.runner, "get_public_ports", lambda server_index: ["5190"])
    monkeypatch.setattr(provision.hardening, "verify_hardening",
                        lambda connection, domain, public_ports: seen.append((connection.username, domain, public_ports)) or [])

    assert build(world).run_verify() is True
    assert seen == [("deploy", "example.com", ["5190"])]


def test_failed_checks_are_counted(entry, monkeypatch):
    failure = provision.hardening.CheckResult("sshd", provision.hardening.FAIL, "password login is on")
    monkeypatch.setattr(provision.runner, "get_public_ports", lambda server_index: [])
    monkeypatch.setattr(provision.hardening, "verify_hardening", lambda connection, domain, public_ports: [failure])
    provisioner = build(World({"deploy": True}))

    assert provisioner.run_verify() is False
    assert provisioner.verify_failures == 1


def test_verification_without_a_login_fails(entry, monkeypatch):
    monkeypatch.setattr(provision.hardening, "verify_hardening", lambda **kwargs: pytest.fail("verified"))

    assert build(World({"deploy": False})).run_verify() is False
