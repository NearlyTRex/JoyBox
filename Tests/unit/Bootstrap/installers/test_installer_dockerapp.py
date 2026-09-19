# Imports
import subprocess

# Third-party imports
import pytest

# Local imports
import installers


###########################################################
# Backup and restore script generation
#
# These are shell scripts built by string concatenation and then handed to a
# remote bash. Nothing else type-checks them, so the generation is worth
# pinning: an unbalanced quote here is a failed backup discovered at restore
# time.
###########################################################

@pytest.fixture
def wordpress(isolated_settings, recording_connection):
    settings = isolated_settings
    settings.set_value("UserData.Wordpress", "wordpress_db_pass", "dbpass")
    settings.set_value("UserData.Wordpress", "wordpress_db_root_pass", "rootpass")
    settings.set_value("UserData.Wordpress", "wordpress_admin_pass", "adminpass")
    settings.set_value("UserData.Wordpress", "wordpress_admin_email", "a@joybox.test")
    return installers.Wordpress(recording_connection)


def assert_valid_shell(script, tmp_path, label):
    path = tmp_path / f"{label}.sh"
    path.write_text(script)
    result = subprocess.run(["bash", "-n", str(path)], capture_output = True, text = True)
    assert result.returncode == 0, f"{label} is not valid shell:\n{result.stderr}"


def test_backup_script_is_valid_shell(wordpress, tmp_path):
    assert_valid_shell(wordpress.build_backup_script(), tmp_path, "backup")


def test_restore_script_is_valid_shell(wordpress, tmp_path):
    assert_valid_shell(wordpress.build_restore_script("latest"), tmp_path, "restore")


def test_backup_is_plain_gzip_without_a_recipient(wordpress, isolated_settings):
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "")
    script = wordpress.build_backup_script()

    assert "gzip -9" in script
    assert "age -r" not in script

    # The checksum step names *.age in both modes by design, so assert on the
    # archive names rather than on the extension appearing anywhere.
    assert ".gz.age" not in script
    assert '> "$DEST/db.sql.gz"' in script


def test_backup_encrypts_when_a_recipient_is_set(wordpress, isolated_settings):
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    script = wordpress.build_backup_script()

    assert "age -r age1example" in script
    assert 'db.sql.gz.age' in script
    assert 'wp_data.tar.gz.age' in script


def test_backup_fails_loudly_when_age_is_missing(wordpress, isolated_settings):

    # Silently writing plaintext because the binary is absent would be the worst
    # possible outcome - the operator would believe the backups were encrypted.
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    script = wordpress.build_backup_script()

    assert "command -v age" in script
    assert "exit 1" in script


def test_checksums_cover_encrypted_artifacts(wordpress, isolated_settings):

    # Checksums are taken over whatever landed on disk. If they only matched
    # *.gz, an encrypted backup would produce an empty SHA256SUMS and restore
    # would verify nothing.
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    script = wordpress.build_backup_script()

    assert "SHA256SUMS" in script
    assert "*.age" in script


def test_backup_publishes_atomically(wordpress):

    # A half-written backup must never be mistaken for a finished one.
    script = wordpress.build_backup_script()
    assert ".partial" in script
    assert 'mv "$DEST"' in script


def test_restore_reads_plain_archives_when_unencrypted(wordpress):
    script = wordpress.build_restore_script("latest")

    # The helper falls back to plain gzip, so backups taken before encryption
    # was enabled still restore.
    assert "archive_stream" in script
    assert 'gzip -dc "$SRC/$1"' in script


def test_restore_refuses_encrypted_archives_without_an_identity(wordpress):
    script = wordpress.build_restore_script("latest")

    assert "backup_age_identity is not set" in script


def test_restore_uses_the_identity_when_given(wordpress):
    script = wordpress.build_restore_script("latest", "/dev/shm/key")

    assert "AGE_IDENTITY=/dev/shm/key" in script
    assert 'age -d -i "$AGE_IDENTITY"' in script


def test_restore_verifies_checksums_before_touching_data(wordpress):
    script = wordpress.build_restore_script("latest")

    # Match the call form, not the function definition, which is emitted first.
    checksum_index = script.index("sha256sum -c SHA256SUMS")
    extract_index = script.index('archive_stream "')
    assert checksum_index < extract_index, \
        "restore must verify checksums before it starts overwriting live data"


def test_components_without_backup_data_do_nothing(isolated_settings, recording_connection):

    # Jenkins deliberately declares no backup items: jenkins_home_dir points at
    # /mnt/repositories, which holds every git repo on the box.
    isolated_settings.set_value("UserData.Jenkins", "jenkins_home_dir", "/mnt/repositories")
    jenkins = installers.Jenkins(recording_connection)

    assert jenkins.has_backup_items() is False
    assert jenkins.backup() is True
    assert recording_connection.commands == []
