# Third-party imports
import pytest

# The slice of WirePlumber 0.4's Lua API the game-mic scripts use: object
# managers that announce matching objects once activated, constraints on
# properties (or on the object itself, for type = "gobject"), the default
# metadata, Log, and load_script recording what a policy file loads
FAKE_HOST = """
host = { managers = {}, objects = {}, loaded = {}, logged = {}, next_id = 100 }

function Constraint (spec)
  return { key = spec[1], value = spec[3], gobject = spec.type == "gobject" }
end

function Interest (spec)
  return spec
end

local function matches (object, interest)
  if interest.type ~= nil and interest.type ~= object.type then
    return false
  end
  for _, constraint in ipairs (interest) do
    local actual = constraint.gobject and object[constraint.key] or object.properties[constraint.key]
    if actual ~= constraint.value then
      return false
    end
  end
  return true
end

function ObjectManager (spec)
  local manager = { interest = spec[1], objects = {}, handlers = {}, active = false }
  function manager:connect (signal, handler)
    self.handlers[signal] = handler
  end
  function manager:activate ()
    self.active = true
    for _, object in ipairs (host.objects) do
      host.offer (self, object)
    end
  end
  function manager:lookup (interest)
    for _, object in ipairs (self.objects) do
      if interest == nil or matches (object, interest) then
        return object
      end
    end
    return nil
  end
  function manager:iterate ()
    local index = 0
    return function ()
      index = index + 1
      return self.objects[index]
    end
  end
  table.insert (host.managers, manager)
  return manager
end

function host.offer (manager, object)
  if manager.active and matches (object, manager.interest) then
    table.insert (manager.objects, object)
    if manager.handlers["object-added"] then
      manager.handlers["object-added"] (manager, object)
    end
  end
end

function host.add (object)
  table.insert (host.objects, object)
  for _, manager in ipairs (host.managers) do
    host.offer (manager, object)
  end
  return object
end

function host.node (properties)
  host.next_id = host.next_id + 1
  return host.add { type = "node", properties = properties, ["bound-id"] = host.next_id }
end

function host.metadata ()
  local metadata = { type = "metadata", properties = { ["metadata.name"] = "default" }, values = {}, handlers = {} }
  function metadata:connect (signal, handler)
    self.handlers[signal] = handler
  end
  function metadata:find (subject, key)
    return (self.values[subject] or {})[key]
  end
  function metadata:set (subject, key, kind, value)
    self.values[subject] = self.values[subject] or {}
    self.values[subject][key] = value
    if self.handlers["changed"] then
      self.handlers["changed"] (self, subject, key, kind, value)
    end
  end
  return host.add (metadata)
end

Log = { info = function (_, message) table.insert (host.logged, message) end }

function load_script (name, args)
  table.insert (host.loaded, { name = name, args = args })
end
"""


# A WirePlumber stand-in: run a script in it, then add nodes and metadata
class FakeWirePlumber:
    def __init__(self, runner):
        self.runner = runner
        runner.lua.execute(FAKE_HOST)
        self.host = runner.globals.host

    # Run a script with a Python dict as its `...` config, or none
    def run(self, path, config = None):
        args = () if config is None else (self.runner.lua.table_from(config),)
        return self.runner.run_file(str(path), *args)

    # A node with these properties, announced to every matching object manager
    def node(self, **properties):
        return self.host.node(self.runner.lua.table_from(properties))

    # The default metadata object, announced the same way
    def metadata(self):
        return self.host.metadata()

    # A metadata value, or None
    def find(self, metadata, subject, key):
        return metadata.find(metadata, subject, key)

    # Set a metadata value as another client would, announcing the change
    def set(self, metadata, subject, key, value):
        metadata.set(metadata, subject, key, "Spa:Id", value)


# A fresh fake WirePlumber per test, traced for Lua coverage when it is on
@pytest.fixture
def wireplumber(lua_runtime):
    return FakeWirePlumber(lua_runtime())
