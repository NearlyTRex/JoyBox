# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import hostsfile, textblock


###########################################################
# Hosts file entries
#
# Points a test domain at a local VM so the workstation's resolver finds it.
# The entries sit in a managed block, because this file also holds whatever
# else the machine needs and none of that may be disturbed.
###########################################################

EXISTING = "127.0.0.1 localhost\n::1 ip6-localhost\n"
ADDRESS = "192.168.122.50"
DOMAIN = "joybox.test"
SUBDOMAINS = ["www", "admin", "cloud"]


@pytest.fixture
def hosts(tmp_path):
    target = tmp_path / "hosts"
    target.write_text(EXISTING)
    return target


def lines_of(path):
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


###########################################################
# Entry building
###########################################################

def test_the_domain_itself_is_first():
    built = hostsfile.build_entries(ADDRESS, DOMAIN, SUBDOMAINS)

    assert built[0] == "%s %s" % (ADDRESS, DOMAIN)


def test_each_subdomain_gets_an_entry():
    built = hostsfile.build_entries(ADDRESS, DOMAIN, SUBDOMAINS)

    assert len(built) == len(SUBDOMAINS) + 1
    assert "%s www.%s" % (ADDRESS, DOMAIN) in built


def test_every_entry_points_at_the_same_address():
    built = hostsfile.build_entries(ADDRESS, DOMAIN, SUBDOMAINS)

    assert all(entry.startswith(ADDRESS + " ") for entry in built)


def test_no_subdomains_still_gives_the_domain():
    built = hostsfile.build_entries(ADDRESS, DOMAIN, [])

    assert built == ["%s %s" % (ADDRESS, DOMAIN)]


def test_the_subdomains_come_from_the_settings(isolated_settings):
    # Listing them here instead would need updating whenever a component with
    # a subdomain of its own is added.
    isolated_settings.set_value("UserData.Cockpit", "cockpit_subdomain", "admin")
    isolated_settings.set_value("UserData.Navidrome", "navidrome_subdomain", "music")
    derived = hostsfile.get_configured_subdomains()

    assert "admin" in derived
    assert "music" in derived


def test_a_blank_subdomain_setting_is_skipped(isolated_settings):
    isolated_settings.set_value("UserData.Cockpit", "cockpit_subdomain", "")

    assert "" not in hostsfile.get_configured_subdomains()


def test_the_derived_subdomains_have_no_duplicates(isolated_settings):
    derived = hostsfile.get_configured_subdomains()

    assert len(derived) == len(set(derived))


def test_the_default_configuration_derives_every_component(isolated_settings):
    derived = hostsfile.get_configured_subdomains()

    assert set(derived) >= {"www", "admin", "cloud", "tools", "tasks", "audio", "music", "aim"}


###########################################################
# Writing
###########################################################

def test_entries_are_written(hosts):
    assert hostsfile.set_entries(
        ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts)) is True
    assert "%s %s" % (ADDRESS, DOMAIN) in lines_of(hosts)


def test_existing_entries_are_kept(hosts):
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))

    assert "127.0.0.1 localhost" in lines_of(hosts)
    assert "::1 ip6-localhost" in lines_of(hosts)


def test_the_entries_sit_in_a_managed_block(hosts):
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))

    assert textblock.has_block(
        hosts.read_text(), hostsfile.MARKER_BEGIN, hostsfile.MARKER_END) is True


def test_writing_twice_does_not_duplicate(hosts):
    # This runs on every rehearsal setup.
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))
    first = hosts.read_text()
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))

    assert hosts.read_text() == first


def test_a_new_address_replaces_the_old_one(hosts):
    # The VM takes a different lease after a snapshot revert.
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))
    hostsfile.set_entries("10.0.0.9", DOMAIN, SUBDOMAINS, hosts_file = str(hosts))

    assert "10.0.0.9 %s" % DOMAIN in lines_of(hosts)
    assert not any(line.startswith(ADDRESS) for line in lines_of(hosts))


def test_pretending_writes_nothing(hosts):
    hostsfile.set_entries(
        ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts), pretend_run = True)

    assert hosts.read_text() == EXISTING


def test_writing_to_a_missing_file_reports_failure(tmp_path):
    assert hostsfile.set_entries(
        ADDRESS, DOMAIN, SUBDOMAINS,
        hosts_file = str(tmp_path / "absent" / "hosts")) is False


###########################################################
# Reading back
###########################################################

def test_the_entries_are_listed(hosts):
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))
    listed = hostsfile.get_entries(hosts_file = str(hosts))

    assert len(listed) == len(SUBDOMAINS) + 1
    assert "%s %s" % (ADDRESS, DOMAIN) in listed


def test_a_file_without_entries_lists_nothing(hosts):
    assert hostsfile.get_entries(hosts_file = str(hosts)) == []


def test_presence_is_reported(hosts):
    assert hostsfile.has_entries(hosts_file = str(hosts)) is False
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))
    assert hostsfile.has_entries(hosts_file = str(hosts)) is True


def test_a_missing_file_has_no_entries(tmp_path):
    assert hostsfile.has_entries(hosts_file = str(tmp_path / "absent")) is False


###########################################################
# Removing
###########################################################

def test_the_entries_are_removed(hosts):
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))

    assert hostsfile.remove_entries(hosts_file = str(hosts)) is True
    assert hostsfile.has_entries(hosts_file = str(hosts)) is False


def test_removal_leaves_the_rest_of_the_file(hosts):
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))
    hostsfile.remove_entries(hosts_file = str(hosts))

    assert hosts.read_text().strip() == EXISTING.strip()


def test_removing_when_there_is_nothing_is_success(hosts):
    assert hostsfile.remove_entries(hosts_file = str(hosts)) is True
    assert hosts.read_text() == EXISTING


def test_removing_twice_is_stable(hosts):
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))
    hostsfile.remove_entries(hosts_file = str(hosts))
    first = hosts.read_text()
    hostsfile.remove_entries(hosts_file = str(hosts))

    assert hosts.read_text() == first


def test_another_tools_block_is_not_touched(hosts):
    # This file is shared with anything else that manages entries in it.
    other = "# BEGIN other tool\n10.0.0.1 other.test\n# END other tool\n"
    hosts.write_text(EXISTING + other)
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))
    hostsfile.remove_entries(hosts_file = str(hosts))

    assert "10.0.0.1 other.test" in lines_of(hosts)


def test_a_round_trip_restores_the_file_exactly(hosts):
    original = hosts.read_text()
    hostsfile.set_entries(ADDRESS, DOMAIN, SUBDOMAINS, hosts_file = str(hosts))
    hostsfile.remove_entries(hosts_file = str(hosts))

    assert hosts.read_text().strip() == original.strip()


###########################################################
# Platform
###########################################################

def test_the_unix_hosts_file_is_etc_hosts(monkeypatch):
    monkeypatch.setattr(hostsfile.platform_info, "is_windows_platform", lambda: False)

    assert hostsfile.get_hosts_file() == "/etc/hosts"


def test_the_windows_hosts_file_is_under_system32(monkeypatch):
    monkeypatch.setattr(hostsfile.platform_info, "is_windows_platform", lambda: True)
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    built = hostsfile.get_hosts_file().replace("/", "\\")

    assert built.endswith("System32\\drivers\\etc\\hosts")
