# Imports
import pytest

# Local imports
import installers
from joybox import serverinfo


###########################################################
# Certificate issuance modes
#
# Every app's nginx template hardcodes /etc/letsencrypt/live/<apex>/, so all
# three modes must land the certificate at that same path.
###########################################################

def build_certbot(settings, connection, tls_mode):
    settings.set_value("UserData.Servers", "server_0_tls_mode", tls_mode)
    return installers.Certbot(connection)


def test_cert_path_uses_the_apex_domain(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    assert certbot.get_cert_dir() == "/etc/letsencrypt/live/joybox.test"


def test_san_list_covers_apex_and_every_subdomain(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")

    assert certbot.fully_qualified_domains[0] == "joybox.test"
    for subdomain in ["www", "admin", "cloud", "tools", "tasks", "audio", "music", "aim"]:
        assert f"{subdomain}.joybox.test" in certbot.fully_qualified_domains


def test_san_list_has_no_empty_entries(isolated_settings, recording_connection):
    # A bare ".joybox.test" makes certbot reject the whole batch.
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    for name in certbot.fully_qualified_domains:
        assert name and not name.startswith("."), f"malformed SAN: {name!r}"


def test_letsencrypt_mode_registers_and_schedules_renewal(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    assert certbot.install() is True

    assert recording_connection.ran("register", "joybox.test")
    assert recording_connection.crontab_added, "letsencrypt mode must schedule renewal"


def test_letsencrypt_mode_refuses_without_a_contact(isolated_settings, recording_connection):
    isolated_settings.set_value("UserData.Servers", "server_0_domain_contact", "")
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")

    assert certbot.install() is False
    assert not recording_connection.ran("register")


def test_local_modes_need_no_contact(isolated_settings, recording_connection):
    isolated_settings.set_value("UserData.Servers", "server_0_domain_contact", "")
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")

    assert certbot.install() is True


def test_selfsigned_mode_never_contacts_lets_encrypt(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    assert certbot.install() is True

    assert not recording_connection.ran("register"), \
        "selfsigned mode must not run the ACME registration"
    assert not recording_connection.crontab_added, \
        "there is nothing to renew, so no cron entry belongs here"
    assert recording_connection.ran("openssl", "req", "-x509")


def test_selfsigned_writes_to_the_shared_cert_path(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.install()

    assert recording_connection.ran("/etc/letsencrypt/live/joybox.test/fullchain.pem")
    assert recording_connection.ran("/etc/letsencrypt/live/joybox.test/privkey.pem")


def test_selfsigned_locks_down_the_private_key(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.install()

    assert recording_connection.ran("chmod", "600", "privkey.pem")
    assert recording_connection.ran("chmod", "644", "fullchain.pem")


def test_selfsigned_covers_every_name_in_the_san_list(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.install()

    # A cert covering only the apex makes every subdomain warn.
    assert recording_connection.ran("subjectAltName", "DNS:joybox.test", "DNS:music.joybox.test")


def test_unknown_mode_fails_rather_than_guessing(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "nonsense")

    assert certbot.install() is False
    assert not recording_connection.ran("register")
    assert not recording_connection.ran("openssl")


def test_mode_defaults_to_letsencrypt(isolated_settings, recording_connection):
    # A server entry that names no mode gets a real certificate.
    isolated_settings.set_value("UserData.Servers", "server_1_domain_name", "example.com")
    serverinfo.select_server(1)
    certbot = installers.Certbot(recording_connection)

    assert certbot.tls_mode == "letsencrypt"


def test_certificate_settings_come_from_the_selected_server(isolated_settings, recording_connection):
    # A test VM alongside a real server must not change the real one's certificate.
    isolated_settings.set_value("UserData.Servers", "server_0_tls_mode", "letsencrypt")
    isolated_settings.set_value("UserData.Servers", "server_1_domain_name", "example.com")
    isolated_settings.set_value("UserData.Servers", "server_1_domain_contact", "vm@example.com")
    isolated_settings.set_value("UserData.Servers", "server_1_tls_mode", "mkcert")

    serverinfo.select_server(1)
    vm = installers.Certbot(recording_connection)
    serverinfo.select_server(0)
    real = installers.Certbot(recording_connection)

    assert (vm.domain_name, vm.domain_contact, vm.tls_mode) == ("example.com", "vm@example.com", "mkcert")
    assert (real.domain_name, real.domain_contact, real.tls_mode) == ("joybox.test", "nobody@joybox.test", "letsencrypt")


def test_uninstall_only_removes_renewal_in_letsencrypt_mode(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.uninstall()

    assert not recording_connection.crontab_removed
