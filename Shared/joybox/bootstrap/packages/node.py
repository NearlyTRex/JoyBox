# Imports
import os
import sys

# Local imports
import joybox.bootstrap.constants as constants
###########################################################
# Node (global npm packages)
###########################################################
node = {}
node[constants.EnvironmentType.LOCAL_UBUNTU] = []
node[constants.EnvironmentType.LOCAL_WINDOWS] = []
node[constants.EnvironmentType.REMOTE_UBUNTU] = []
node[constants.EnvironmentType.REMOTE_WINDOWS] = []

###########################################################
# Node - Local Ubuntu
###########################################################
node[constants.EnvironmentType.LOCAL_UBUNTU] += [

    # AI
    {"id": "@openai/codex", "name": "Codex CLI", "description": "OpenAI coding-agent harness", "category": "AI"},
    {"id": "ccusage", "name": "ccusage", "description": "Claude Code usage monitoring", "category": "AI"},
    {"id": "opencode-ai", "name": "OpenCode", "description": "Open-source coding-agent harness", "category": "AI"},
    {"id": "promptfoo", "name": "Promptfoo", "description": "Prompt eval harness with deterministic assertions", "category": "AI"},
]

###########################################################
# Node - Remote Ubuntu
###########################################################
node[constants.EnvironmentType.REMOTE_UBUNTU] += [

    # AI
    {"id": "ccusage", "name": "ccusage", "description": "Claude Code usage monitoring", "category": "AI"},
]
