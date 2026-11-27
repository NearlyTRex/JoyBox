# Imports
import importlib
import signal
import time
import ntpath

# Local imports
from joybox import logger
from joybox import runtime

# Get psutil, imported on first use
def _get_psutil():
    return importlib.import_module("psutil")

###########################################################
# Process management
###########################################################

# The errors psutil raises for a process that has exited or cannot be read
def get_process_errors():
    psutil = _get_psutil()
    return (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess)

# Whether a process has one of the names, exactly or by basename; one that has
# exited or cannot be read has none
def has_process_name(proc, process_names):
    try:
        name = proc.name()
    except get_process_errors():
        return False
    return any(process_name == name or ntpath.basename(process_name) == ntpath.basename(name)
               for process_name in process_names)

# Running psutil processes whose name or basename matches one given; empty when they cannot be listed
def find_active_named_processes(process_names = ()):
    psutil = _get_psutil()
    try:
        candidates = list(psutil.process_iter())
    except get_process_errors():
        return []
    return [proc for proc in candidates if has_process_name(proc, process_names)]

# Send a kill to every running process with a matching name, logging any that refuse
def kill_active_named_processes(process_names = ()):
    for proc in find_active_named_processes(process_names):
        try:
            proc.kill()
        except get_process_errors() as e:
            logger.log_error(e)

# Send Ctrl+C (SIGINT off Windows) to every running process with a matching name
def interrupt_active_named_processes(process_names = ()):
    number = signal.CTRL_C_EVENT if hasattr(signal, "CTRL_C_EVENT") else signal.SIGINT
    for proc in find_active_named_processes(process_names):
        try:
            proc.send_signal(number)
        except get_process_errors() as e:
            logger.log_error(e)

# Wait for one process to finish, until timeout seconds after start_time
def wait_for_process(proc, start_time, timeout):
    logger.log_info("Waiting for process %s (pid=%d)..." % (proc.name(), proc.pid))
    while proc.is_running():
        if timeout and time.time() - start_time > timeout:
            logger.log_warning("Timeout after %d seconds waiting for %s (pid=%d)" % (timeout, proc.name(), proc.pid))
            return
        runtime.sleep_program(1)
    logger.log_info("Process (pid=%d) finished" % proc.pid)

# Block until each matching process exits, sharing one timeout in seconds counted from the call
def wait_for_named_processes(process_names = (), timeout = 1200):
    psutil = _get_psutil()
    start_time = time.time()
    for proc in find_active_named_processes(process_names):
        try:
            wait_for_process(proc, start_time, timeout)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            logger.log_info("Process (pid=%d) finished" % proc.pid)
        except psutil.AccessDenied as e:
            logger.log_warning("Access denied while waiting for process: %s" % e)
