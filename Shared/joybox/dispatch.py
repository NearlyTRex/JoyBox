# Imports
import inspect

###########################################################
# Dispatch
#
# A family of handlers is run through one call site, but each handler names only
# the options it reads. The call site offers every option and each handler is
# given the ones its signature takes.
###########################################################

# Call a handler with the offered options its signature names, leaving out the rest
def call_with_options(handler, *args, **options):
    parameters = inspect.signature(handler).parameters
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()):
        return handler(*args, **options)
    return handler(*args, **{name: value for name, value in options.items() if name in parameters})
