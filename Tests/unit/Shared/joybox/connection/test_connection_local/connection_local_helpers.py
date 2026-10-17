###########################################################
# ConnectionLocal
#
# Every filesystem operation has two implementations: one that delegates to
# the shared fileops primitives, and one that shells out under sudo. The sudo
# path runs as root, so the command it builds is worth pinning exactly.
###########################################################

def only(calls, name = None):
    matching = [call for call in calls if name is None or call["name"] == name]
    assert len(matching) == 1, "expected one %s call, recorded %d" % (name or "command", len(matching))
    return matching[0]


class FakeProcesses:
    # Stands in for the subprocess module; each call is recorded with the
    # options it was started with.
    PIPE = -1
    STDOUT = -2

    def __init__(self):
        self.calls = []
        self.output = b""
        self.code = 0
        self.error = None
        self.chunks = []

    def _start(self, cmd, kwargs):
        self.calls.append({"cmd": cmd, **kwargs})
        if self.error:
            raise self.error

    def run(self, cmd, **kwargs):
        self._start(cmd, kwargs)
        return type("Completed", (), {"stdout": self.output})()

    def call(self, cmd, **kwargs):
        self._start(cmd, kwargs)
        for name in ["stdout", "stderr"]:
            if hasattr(kwargs[name], "write"):
                kwargs[name].write("%s\n" % name)
        return self.code

    def Popen(self, cmd, **kwargs):
        self._start(cmd, kwargs)
        fake = self
        chunks = iter(self.chunks + [b""])

        class Process:
            stdout = type("Pipe", (), {"read": staticmethod(lambda size: next(chunks))})()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def wait(self):
                return fake.code
        return Process()


SUDO_OPERATIONS = [
    ("make_directory", ("/opt/app",)),
    ("remove_file_or_directory", ("/opt/app",)),
    ("copy_file_or_directory", ("/tmp/a", "/opt/a")),
    ("move_file_or_directory", ("/tmp/a", "/opt/a")),
    ("link_file_or_directory", ("/tmp/a", "/opt/a")),
    ("extract_tar_archive", ("/tmp/a.tar", "/opt/a")),
    ("transfer_files", ("/tmp/a", "/opt/a")),
    ("write_file", ("/opt/a", "contents")),
    ("read_file", ("/opt/a",)),
    ("download_file", ("https://example.test/a", "/opt/a")),
    ("change_owner", ("/opt/a", "app:app")),
    ("change_permission", ("/opt/a", "750")),
]
