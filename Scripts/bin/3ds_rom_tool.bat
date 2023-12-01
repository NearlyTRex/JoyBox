@echo off
if not exist %USERPROFILE%\.venv\ (
    python -m venv %USERPROFILE%\.venv
)
%USERPROFILE%\.venv\Scripts\python "%~dp03ds_rom_tool.py" %*
