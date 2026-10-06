# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.installers as installers
from joybox import runoptions
from fakes import RecordingConnection


class FailingWrites(RecordingConnection):
    def __init__(self, failing_fragment, **kwargs):
        super().__init__(**kwargs)
        self.failing_fragment = failing_fragment

    def write_file(self, src, contents, sudo = False):
        if self.failing_fragment in src:
            self._record("write_file", src, contents, sudo = sudo)
            return False
        return super().write_file(src, contents, sudo = sudo)


def build_oscar(connection):
    return installers.Oscar(connection, runoptions.RunFlags(verbose = False))


def test_nginx_config_installs_the_stream_entry_and_the_api_vhost(isolated_settings):
    connection = RecordingConnection()
    oscar = build_oscar(connection)

    assert oscar.install_nginx_config()
    assert connection.ran("install_stream_conf", "/tmp/oscar.stream.conf")
    assert connection.ran("link_stream_conf", "oscar.stream.conf")
    assert connection.written("oscar.conf")


@pytest.mark.parametrize("fragment", ["oscar.stream.conf", "oscar.conf"])
def test_nginx_config_fails_when_a_config_cannot_be_written(isolated_settings, fragment):
    connection = FailingWrites(fragment)
    oscar = build_oscar(connection)

    assert not oscar.install_nginx_config()


def test_unwritable_stream_config_installs_nothing(isolated_settings):
    connection = FailingWrites("oscar.stream.conf")
    oscar = build_oscar(connection)

    oscar.install_nginx_config()
    assert not connection.ran("install_stream_conf")
    assert not connection.written("/tmp/oscar.conf")


def test_uninstall_removes_the_stream_entry_and_the_api_vhost(isolated_settings):
    connection = RecordingConnection()
    oscar = build_oscar(connection)

    assert oscar.uninstall_nginx_config()
    assert connection.ran("remove_stream_conf", "oscar.stream.conf")


def test_an_unwritable_dockerfile_stops_the_install(isolated_settings):
    connection = FailingWrites("oscar.Dockerfile")
    oscar = build_oscar(connection)

    assert not oscar.install()
    assert connection.moved == []
    assert not connection.ran("compose")
