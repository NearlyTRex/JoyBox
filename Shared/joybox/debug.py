# Imports
import os
import inspect

###########################################################
# Debug utilities
###########################################################

# Get source info
def get_source_info(depth = 1):
    frame = inspect.currentframe()
    for _ in range(depth + 1):
        if frame is not None:
            frame = frame.f_back
    if frame is None:
        return "(unknown:0)"
    file_name = os.path.basename(frame.f_code.co_filename)
    line_number = frame.f_lineno
    return f"({file_name}:{line_number})"

# Get backtrace
def get_backtrace(skip = 0):
    stack = inspect.stack()
    backtrace = []
    for frame_info in stack[skip + 1:]:
        filename = frame_info.filename
        lineno = frame_info.lineno
        name = frame_info.function
        backtrace.append(f"File: {filename}, Line: {lineno}, Function: {name}")
    return "\n" + "\n".join(backtrace)
