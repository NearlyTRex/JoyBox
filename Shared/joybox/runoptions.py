# Execution flags and options for command running and connections.

# Imports
import copy

###########################################################
# Run flags
###########################################################
class RunFlags:
    def __init__(
        self,
        verbose = True,
        force = False,
        pretend_run = False,
        exit_on_failure = True,
        skip_existing = False):
        self.verbose = verbose
        self.force = force
        self.pretend_run = pretend_run
        self.exit_on_failure = exit_on_failure
        self.skip_existing = skip_existing

    def copy(self):
        return copy.deepcopy(self)

    def set(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise AttributeError(f"RunFlags has no attribute '{key}'")
        return self

###########################################################
# Run options
###########################################################
class RunOptions:
    def __init__(
        self,
        cwd = None,
        env = None,
        shell = False,
        creationflags = 0,
        stdout = None,
        stderr = None,
        include_stderr = False):
        self.cwd = cwd
        if not env:
            env = {}
        self.env = env
        self.shell = shell
        self.creationflags = creationflags
        self.stdout = stdout
        self.stderr = stderr
        self.include_stderr = include_stderr

    def copy(self):
        return copy.deepcopy(self)

    def set(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise AttributeError(f"RunOptions has no attribute '{key}'")
        return self
