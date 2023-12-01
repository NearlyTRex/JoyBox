@echo off
if not exist %USERPROFILE%\.venv\ (
    python -m venv %USERPROFILE%\.venv
)
%USERPROFILE%\.venv\Scripts\python "%~dp0clean_json_files.py" %*
