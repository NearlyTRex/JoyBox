# Running a command that is ready to run: starting it, streaming its output and
# waiting for it and the processes it blocks on. command.py prepares commands
# for prefixes and cleans up after them around this; setting up a prefix runs
# its own tools through here, so it never loops back into that preparation.

# Imports
import os
import contextlib
import subprocess
import threading

# Local imports
from joybox import cmdline
from joybox import logger
from joybox import paths
from joybox import process
from joybox import runtime
from joybox.commandbase import print_command

# Wait for a command to finish, stopping it once it has run for timeout seconds
def wait_for_command(proc, timeout):
    try:
        proc.wait(timeout = timeout)
    except subprocess.TimeoutExpired:
        logger.log_warning("The command ran for more than %s seconds and was stopped" % timeout)
        proc.kill()
        proc.wait()

# Where the child's stderr goes: merged into stdout (OS-level, order-preserving) for
# include_stderr capture, piped separately when streaming it live or writing it to a
# file, otherwise inherited from the terminal (so it still shows up by default)
def _get_stderr_arg(options, pipe_stderr):
    if options.include_stderr() and not pipe_stderr:
        return subprocess.STDOUT
    if pipe_stderr:
        return subprocess.PIPE
    return None

# Open the process with its stdout piped as text, line buffered, and stdin piped when there is input
def _open_streamed_process(cmd, options, stderr_arg, stdin_input):
    return subprocess.Popen(
        cmd,
        shell = options.is_shell(),
        cwd = options.get_cwd(),
        env = options.get_env(),
        creationflags = options.get_creationflags(),
        stdout = subprocess.PIPE,
        stderr = stderr_arg,
        stdin = subprocess.PIPE if stdin_input is not None else None,
        text = True,
        errors = "ignore",
        bufsize = 1)

# Copy each line of a stream to the captured lines, the log and the target file as asked.
# readline() rather than "for line in pipe", which read-ahead-buffers and defeats
# real-time streaming; an empty line is end of stream
def _pump_stream(stream, capture, log, target, output_lines):
    for line in iter(stream.readline, ""):
        if capture:
            output_lines.append(line)
        if log:
            logger.log_info(line.strip())
        if target:
            target.write(line)
            target.flush()

# Start a thread pumping each (stream, capture, log, target) into the shared output lines
def _start_pump_threads(pumps, output_lines):
    threads = [threading.Thread(target = _pump_stream, args = pump + (output_lines,)) for pump in pumps]
    for t in threads:
        t.start()
    return threads

# Write the input to the process and close its stdin, warning when it exits before reading it all
def _write_stdin_input(proc, stdin_input):
    try:
        proc.stdin.write(stdin_input)
        proc.stdin.close()
    except BrokenPipeError:
        logger.log_warning("The command exited before reading all of its input")

# Run a command, pumping its output streams in real time
def run_streamed_command(
    cmd,
    options,
    capture_output = True,
    log_stdout = False,
    log_stderr = False):

    # Determine output file handling
    stdout_path = options.get_stdout() if paths.is_path_valid(options.get_stdout()) else None
    stderr_path = options.get_stderr() if paths.is_path_valid(options.get_stderr()) else None
    stdin_input = options.get_stdin_input()

    # Determine stderr disposition
    pipe_stderr = log_stderr or stderr_path is not None
    capture_stderr = options.include_stderr() and capture_output
    stderr_arg = _get_stderr_arg(options, pipe_stderr)

    # Get context stack
    with contextlib.ExitStack() as stack:
        stdout_target = stack.enter_context(open(stdout_path, "w", encoding = "utf-8")) if stdout_path else None
        stderr_target = stack.enter_context(open(stderr_path, "w", encoding = "utf-8")) if stderr_path else None

        # Open process
        proc = stack.enter_context(_open_streamed_process(cmd, options, stderr_arg, stdin_input))

        # Run real-time I/O threads
        output_lines = []
        pumps = [(proc.stdout, capture_output, log_stdout, stdout_target)]
        if pipe_stderr:
            pumps.append((proc.stderr, capture_stderr, log_stderr, stderr_target))
        threads = _start_pump_threads(pumps, output_lines)
        if stdin_input is not None:
            _write_stdin_input(proc, stdin_input)
        wait_for_command(proc, options.get_timeout())
        for t in threads:
            t.join()
    return (cmdline.clean_command_output("".join(output_lines).strip()), proc.returncode)

# Launch a command detached from this one, in its own session, with no streams;
# the caller gets the process and nothing waits for it
def launch_daemon(cmd, options):
    return subprocess.Popen(
        cmd,
        shell = options.is_shell(),
        cwd = options.get_cwd(),
        env = options.get_env(),
        creationflags = options.get_creationflags() | getattr(subprocess, "DETACHED_PROCESS", 0),
        stdout = subprocess.DEVNULL,
        stderr = subprocess.DEVNULL,
        stdin = subprocess.DEVNULL,
        start_new_session = os.name != "nt")

# Wait for the processes a command blocks on
def wait_for_blocking_processes(options):
    if isinstance(options.get_blocking_processes(), list) and len(options.get_blocking_processes()) > 0:
        process.wait_for_named_processes(options.get_blocking_processes())

# Run a command on this terminal's own streams, for TUI apps, then wait for what it blocks on
def _run_passthrough_command(cmd, options):
    returncode = subprocess.call(
        cmd,
        shell = options.is_shell(),
        cwd = options.get_cwd(),
        env = options.get_env())
    wait_for_blocking_processes(options)
    return ("", returncode)

# Run a command with its output discarded, then wait for what it blocks on
def _run_suppressed_command(cmd, options):
    with subprocess.Popen(
        cmd,
        shell = options.is_shell(),
        cwd = options.get_cwd(),
        env = options.get_env(),
        creationflags = options.get_creationflags(),
        stdout = subprocess.DEVNULL,
        stderr = subprocess.DEVNULL) as proc:
        wait_for_command(proc, options.get_timeout())
    wait_for_blocking_processes(options)
    return ("", proc.returncode)

# Run a command as it is, with no pre- or post-processing, and wait for the
# processes it blocks on unless it is left running as a daemon
def run_prepared_command(
    cmd,
    options,
    capture_output = True,
    log_stdout = False,
    log_stderr = False,
    verbose = False):

    # Log command
    if verbose:
        print_command(cmd)

    # Handle shell commands
    if options.is_shell():
        cmd = cmdline.create_command_string(cmd)

    # Passthrough mode - inherit stdin/stdout/stderr directly (for TUI apps)
    if options.is_passthrough():
        return _run_passthrough_command(cmd, options)

    # Daemon mode - detach and return without waiting or cleaning up after it
    if options.is_daemon():
        launch_daemon(cmd, options)
        runtime.sleep_program(0.5)
        return ("", 0)

    # Suppressed output - discard streams, just wait
    if options.is_output_suppressed():
        return _run_suppressed_command(cmd, options)

    # Run with streamed output
    output, returncode = run_streamed_command(
        cmd = cmd,
        options = options,
        capture_output = capture_output,
        log_stdout = log_stdout,
        log_stderr = log_stderr)
    wait_for_blocking_processes(options)
    return (output, returncode)

# Run a command as it is and return its exit code, logging its output
def run_prepared_returncode_command(
    cmd,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if pretend_run:
        return 0
    try:
        _, returncode = run_prepared_command(
            cmd = cmdline.create_command_list(cmd),
            options = options,
            capture_output = False,
            log_stdout = True,
            log_stderr = True,
            verbose = verbose)
        return returncode
    except (OSError, ValueError) as e:
        if verbose or exit_on_failure:
            logger.log_error(e, quit_program = exit_on_failure)
        return 1
