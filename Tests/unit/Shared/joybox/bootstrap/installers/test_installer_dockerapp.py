# Imports
import subprocess

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.installers as installers
###########################################################
# Backup and restore script generation
#
# Shell built by string concatenation and handed to a remote bash. An unbalanced
# quote here is a failed backup discovered at restore time.
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
    result = subprocess.run(["bash", "-n", str(path)], capture_output = True, text = True, check = False)
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

    # The checksum step names *.age in both modes, so assert on archive names.
    assert ".gz.age" not in script
    assert '> "$DEST/db.sql.gz"' in script


def test_backup_encrypts_when_a_recipient_is_set(wordpress, isolated_settings):
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    script = wordpress.build_backup_script()

    assert "age -r age1example" in script
    assert 'db.sql.gz.age' in script
    assert 'wp_data.tar.gz.age' in script


def test_backup_fails_loudly_when_age_is_missing(wordpress, isolated_settings):
    # Writing plaintext because the binary is absent would be worse than failing.
    isolated_settings.set_value("UserData.Backup", "backup_age_recipient", "age1example")
    script = wordpress.build_backup_script()

    assert "command -v age" in script
    assert "exit 1" in script


def test_checksums_cover_encrypted_artifacts(wordpress, isolated_settings):
    # Matching only *.gz would leave an encrypted backup with empty checksums.
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

    # Plain gzip fallback keeps pre-encryption backups restorable.
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

    # Match the call form, not the definition emitted above it.
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


###########################################################
# Installed state
#
# Installed means every install step finished (the marker) and the app is
# still up (running, healthy containers); either alone is not enough.
###########################################################

HEALTHY = ("wordpress-db-1\trunning\tUp 5 minutes (healthy)\n"
           "wordpress-wordpress-1\trunning\tUp 4 minutes (healthy)\n"
           "navidrome-1\texited\tExited (1) 2 hours ago\n")


def build_with_containers(isolated_settings, listing, marked = True):
    from fakes import RecordingConnection
    connection = RecordingConnection(command_output = {"docker ps -a": listing})
    wordpress = installers.Wordpress(connection)
    if marked:
        connection.existing_paths.add(wordpress.get_install_marker())
    return wordpress


def test_no_containers_is_not_installed(isolated_settings):
    assert not build_with_containers(isolated_settings, "").is_installed()


def test_running_healthy_containers_are_installed(isolated_settings):
    assert build_with_containers(isolated_settings, HEALTHY).is_installed()


def test_healthy_containers_without_the_marker_are_not_installed(isolated_settings):
    assert not build_with_containers(isolated_settings, HEALTHY, marked = False).is_installed()


def test_an_unhealthy_container_is_not_installed(isolated_settings):
    listing = ("wordpress-db-1\trunning\tUp 5 minutes (unhealthy)\n"
               "wordpress-wordpress-1\tcreated\tCreated\n")
    assert not build_with_containers(isolated_settings, listing).is_installed()


def test_a_stopped_container_is_not_installed(isolated_settings):
    listing = ("wordpress-db-1\trunning\tUp 5 minutes (healthy)\n"
               "wordpress-wordpress-1\texited\tExited (0) 1 minute ago\n")
    assert not build_with_containers(isolated_settings, listing).is_installed()


def test_a_finished_install_writes_the_marker(wordpress, recording_connection, monkeypatch):
    monkeypatch.setattr(wordpress, "post_install", lambda: True)

    assert wordpress.install()
    assert wordpress.get_install_marker() in recording_connection.written_files


def test_a_failed_post_install_leaves_no_marker(wordpress, recording_connection, monkeypatch):
    monkeypatch.setattr(wordpress, "post_install", lambda: False)

    assert not wordpress.install()
    assert wordpress.get_install_marker() not in recording_connection.written_files
    assert wordpress.get_install_marker() in recording_connection.removed_paths
