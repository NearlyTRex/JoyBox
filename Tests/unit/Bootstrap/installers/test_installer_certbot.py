# Imports
import pytest

# Local imports
import installers


###########################################################
# Certificate issuance modes
#
# All three modes must land the certificate at the same path, because every
# app's nginx template hardcodes /etc/letsencrypt/live/<apex>/. That invariant
# is what keeps the local modes from needing template changes.
###########################################################

def build_certbot(settings, connection, tls_mode):
    settings.set_value("UserData.Servers", "tls_mode", tls_mode)
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

    # A removed component that left its settings lookup behind would produce a
    # bare ".joybox.test", which certbot rejects for the whole batch.
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    for name in certbot.fully_qualified_domains:
        assert name and not name.startswith("."), f"malformed SAN: {name!r}"


def test_letsencrypt_mode_registers_and_schedules_renewal(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "letsencrypt")
    assert certbot.install() is True

    assert recording_connection.ran("register", "joybox.test")
    assert recording_connection.crontab_added, "letsencrypt mode must schedule renewal"


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

    # A cert covering only the apex would make every subdomain warn separately
    assert recording_connection.ran("subjectAltName", "DNS:joybox.test", "DNS:music.joybox.test")


def test_unknown_mode_fails_rather_than_guessing(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "nonsense")

    assert certbot.install() is False
    assert not recording_connection.ran("register")
    assert not recording_connection.ran("openssl")


def test_mode_defaults_to_letsencrypt(isolated_settings, recording_connection):

    # An existing config predating tls_mode must keep behaving exactly as before.
    isolated_settings.reset()
    isolated_settings.set_settings_file(isolated_settings.get_settings_file())
    isolated_settings.set_value("UserData.Servers", "domain_name", "example.com")
    certbot = installers.Certbot(recording_connection)

    assert certbot.tls_mode == "letsencrypt"


def test_uninstall_only_removes_renewal_in_letsencrypt_mode(isolated_settings, recording_connection):
    certbot = build_certbot(isolated_settings, recording_connection, "selfsigned")
    certbot.uninstall()

    assert not recording_connection.crontab_removed
