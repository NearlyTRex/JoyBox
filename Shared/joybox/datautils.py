# Imports
import importlib
import time
import collections.abc

# Local imports
from joybox import config
from joybox import logger

# Get mergedeep, imported on first use
def _get_mergedeep():
    return importlib.import_module("mergedeep")

###########################################################
# Data structure utilities
###########################################################

# Deep-merge dict2 into dict1 with the mergedeep strategy the merge type picks; whichever
# side is a dict when only one is, dict1 unchanged on a type clash, None when neither is
def merge_dictionaries(dict1, dict2, merge_type = None):
    if isinstance(dict1, dict) and isinstance(dict2, dict):
        mergedeep = _get_mergedeep()
        try:
            if merge_type == config.MergeType.REPLACE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.REPLACE)
            if merge_type == config.MergeType.ADDITIVE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.ADDITIVE)
            if merge_type == config.MergeType.SAFE_REPLACE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.TYPESAFE_REPLACE)
            if merge_type == config.MergeType.SAFE_ADDITIVE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.TYPESAFE_ADDITIVE)
            return mergedeep.merge(dict1, dict2)
        except TypeError:
            return dict1
    elif isinstance(dict1, dict) and not isinstance(dict2, dict):
        return dict1
    elif not isinstance(dict1, dict) and isinstance(dict2, dict):
        return dict2
    else:
        return None

# The sorted union of both lists without duplicates; whichever is a list when only one is
def merge_lists(list1, list2):
    if isinstance(list1, list) and isinstance(list2, list):
        return sorted(set(list1 + list2))
    if isinstance(list1, list) and not isinstance(list2, list):
        return list1
    if not isinstance(list1, list) and isinstance(list2, list):
        return list2
    return None

# Merge two values by kind: dicts deep-merge, lists union, two scalars pair into a list,
# and a lone non-empty value comes back as is; None when both are empty
def merge_data(data1, data2, merge_type = None):
    if isinstance(data1, dict) or isinstance(data2, dict):
        return merge_dictionaries(
            dict1 = data1,
            dict2 = data2,
            merge_type = merge_type)
    if isinstance(data1, list) or isinstance(data2, list):
        return merge_lists(
            list1 = data1,
            list2 = data2)
    if data1 and data2:
        return [data1, data2]
    if data1 and not data2:
        return data1
    if not data1 and data2:
        return data2
    return None

# Drop lines that repeat the line before them, keeping the first of each run
def deduplicate_adjacent_lines(lines):
    new_lines = []
    for line in lines:
        if len(new_lines) == 0 or line != new_lines[-1]:
            new_lines.append(line)
    return new_lines

# Determine if container is iterable
def is_iterable_container(obj):
    return isinstance(obj, collections.abc.Iterable)

# Determine if container is iterable non-string
def is_iterable_non_string(obj):
    if isinstance(obj, str):
        return False
    return is_iterable_container(obj)

# The first (key, value) whose string value contains the search text, recursing into
# nested dicts and limited to the given keys when any; empty list when none match
def search_dictionary(data, search_value, search_keys = None):
    search_keys = [] if search_keys is None else search_keys
    if not isinstance(data, dict):
        return []
    for key, value in data.items():
        if not search_keys or key in search_keys:
            if isinstance(value, str) and search_value in value:
                return [(key, value)]
        if isinstance(value, dict):
            nested_match = search_dictionary(value, search_value, search_keys)
            if nested_match:
                return nested_match
    return []

###########################################################
# Retry utilities
###########################################################

# Run the cleanup between attempts, warning instead of raising when it fails with a retry_on error
def _run_retry_cleanup(cleanup_func, retry_on, verbose):
    try:
        cleanup_func()
    except retry_on as cleanup_error:
        if verbose:
            logger.log_warning("Cleanup failed: %s" % str(cleanup_error))

# Log, when verbose, that every attempt failed
def _log_retries_exhausted(operation_name, max_retries, verbose):
    if verbose and operation_name:
        logger.log_error("%s failed after %d attempts" % (operation_name, max_retries))
    elif verbose:
        logger.log_error("Operation failed after %d attempts" % max_retries)

# Retry function with exponential backoff and cleanup, retrying when it raises one of the
# retry_on errors or returns None after such a failure; a first-attempt None is the answer
def retry_with_backoff(
    func,
    retry_on,
    cleanup_func = None,
    max_retries = 3,
    initial_delay = 1,
    backoff_factor = 2,
    verbose = False,
    operation_name = None):
    for attempt in range(max_retries):
        try:
            result = func()
            if result is not None or attempt == 0:
                return result
            reason = "no result"
        except retry_on as e:
            reason = str(e)
        if verbose and operation_name:
            logger.log_warning("%s failed (attempt %d/%d): %s" % (operation_name, attempt + 1, max_retries, reason))
        elif verbose:
            logger.log_warning("Operation failed (attempt %d/%d): %s" % (attempt + 1, max_retries, reason))
        if cleanup_func:
            _run_retry_cleanup(cleanup_func, retry_on, verbose)
        if attempt == max_retries - 1:
            _log_retries_exhausted(operation_name, max_retries, verbose)
            return None
        delay = initial_delay * (backoff_factor ** attempt)
        if verbose:
            logger.log_info("Retrying in %.1f seconds..." % delay)
        time.sleep(delay)
    return None
