# JoyBox shared core library.
#
# Dependency-free (stdlib-only) implementations of utility logic shared by both
# the Bootstrap and Scripts trees. Both consume these modules directly rather
# than maintaining parallel copies. Where behavior legitimately differs by
# context (e.g. POSIX/SSH vs. Windows command quoting), the variants live here
# behind a single delegating entrypoint.
