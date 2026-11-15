# The module, of those given, that defines a name
def owner_of(name, *modules):
    return next(module for module in modules if hasattr(module, name))
