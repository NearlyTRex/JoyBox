# Imports
import signal
import time
import ntpath

# Local imports
import system
import logger

###########################################################
# Process management
###########################################################

# Find active processes
def find_active_named_processes(process_names = []):
    import psutil
    process_objs = []
    try:
        for proc in psutil.process_iter():
            for process_name in process_names:
                if process_name == proc.name():
                    process_objs.append(proc)
                elif ntpath.basename(process_name) == ntpath.basename(proc.name()):
                    process_objs.append(proc)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        pass
    return process_objs

# Kill active processes
def kill_active_named_processes(process_names = []):
    import psutil
    try:
        for proc in find_active_named_processes(process_names):
            proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logger.log_error(e)

# Interrupt active processes
def interrupt_active_named_processes(process_names = []):
    import psutil
    try:
        for proc in find_active_named_processes(process_names):
            if hasattr(signal, "CTRL_C_EVENT"):
                proc.send_signal(signal.CTRL_C_EVENT)
            else:
                proc.send_signal(signal.SIGINT)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        logger.log_error(e)

# Wait for processes
def wait_for_named_processes(process_names = [], timeout = 1200):
    import psutil
    try:
        start_time = time.time()
        for proc in find_active_named_processes(process_names):
            logger.log_info("Waiting for process %s (pid=%d)..." % (proc.name(), proc.pid))
            while True:
                if not proc.is_running():
                    logger.log_info("Process %s (pid=%d) finished" % (proc.name(), proc.pid))
                    break
                elapsed = time.time() - start_time
                if timeout and elapsed > timeout:
                    logger.log_warning("Timeout after %d seconds waiting for %s (pid=%d)" % (timeout, proc.name(), proc.pid))
                    break
                system.sleep_program(1)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        pass  # Process already finished, which is fine
    except psutil.AccessDenied as e:
        logger.log_warning("Access denied while waiting for process: %s" % e)
