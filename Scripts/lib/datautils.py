# Imports
import time
import collections.abc

# Local imports
import config
import logger

###########################################################
# Data structure utilities
###########################################################

# Merge dictionaries
def merge_dictionaries(dict1, dict2, merge_type = None):
    if isinstance(dict1, dict) and isinstance(dict2, dict):
        try:
            import mergedeep
            if merge_type == config.MergeType.REPLACE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.REPLACE)
            elif merge_type == config.MergeType.ADDITIVE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.ADDITIVE)
            elif merge_type == config.MergeType.SAFE_REPLACE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.TYPESAFE_REPLACE)
            elif merge_type == config.MergeType.SAFE_ADDITIVE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.TYPESAFE_ADDITIVE)
            else:
                return mergedeep.merge(dict1, dict2)
        except:
            return dict1
    elif isinstance(dict1, dict) and not isinstance(dict2, dict):
        return dict1
    elif not isinstance(dict1, dict) and isinstance(dict2, dict):
        return dict2
    else:
        return None

# Merge lists
def merge_lists(list1, list2, merge_type = None):
    if isinstance(list1, list) and isinstance(list2, list):
        return sorted(set(list1 + list2))
    elif isinstance(list1, list) and not isinstance(list2, list):
        return list1
    elif not isinstance(list1, list) and isinstance(list2, list):
        return list2
    else:
        return None

# Merge data
def merge_data(data1, data2, merge_type = None):
    if isinstance(data1, dict) or isinstance(data2, dict):
        return merge_dictionaries(
            dict1 = data1,
            dict2 = data2,
            merge_type = merge_type)
    elif isinstance(data1, list) or isinstance(data2, list):
        return merge_lists(
            list1 = data1,
            list2 = data2,
            merge_type = merge_type)
    else:
        if data1 and data2:
            return [data1, data2]
        elif data1 and not data2:
            return data1
        elif not data1 and data2:
            return data2
        else:
            return None

# Deduplicate adjacent lines
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

# Search dictionary
def search_dictionary(data, search_value, search_keys = []):
    if not isinstance(data, dict):
        return []
    for key, value in data.items():
        if not search_keys or key in search_keys:
            if isinstance(value, str) and search_value in value:
                return [(key, value)]
        if isinstance(value, dict):
            return search_dictionary(value, search_value, search_keys)
    return []

###########################################################
# Retry utilities
###########################################################

# Retry function with exponential backoff and cleanup
def retry_with_backoff(
    func,
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
        except Exception as e:
            if verbose and operation_name:
                logger.log_warning("%s failed (attempt %d/%d): %s" % (operation_name, attempt + 1, max_retries, str(e)))
            elif verbose:
                logger.log_warning("Operation failed (attempt %d/%d): %s" % (attempt + 1, max_retries, str(e)))
            if cleanup_func:
                try:
                    cleanup_func()
                except Exception as cleanup_error:
                    if verbose:
                        logger.log_warning("Cleanup failed: %s" % str(cleanup_error))
            if attempt == max_retries - 1:
                if verbose and operation_name:
                    logger.log_error("%s failed after %d attempts" % (operation_name, max_retries))
                elif verbose:
                    logger.log_error("Operation failed after %d attempts" % max_retries)
                return None
            delay = initial_delay * (backoff_factor ** attempt)
            if verbose:
                logger.log_info("Retrying in %.1f seconds..." % delay)
            time.sleep(delay)
    return None
