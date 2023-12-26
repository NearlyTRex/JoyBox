@echo off

REM Tools
winget install -e --id Git.Git
winget install -e --id Mozilla.Firefox
winget install -e --id Sandboxie.Plus
winget install -e --id mcmilk.7zip-zstd
winget install -e --id Python.Python.3.11

REM Python
python -m venv %USERPROFILE%\.venv
%USERPROFILE%\.venv\Scripts\pip install --upgrade pip
%USERPROFILE%\.venv\Scripts\pip install --upgrade wheel
%USERPROFILE%\.venv\Scripts\pip install --upgrade psutil
%USERPROFILE%\.venv\Scripts\pip install --upgrade selenium
%USERPROFILE%\.venv\Scripts\pip install --upgrade requests
%USERPROFILE%\.venv\Scripts\pip install --upgrade pathlib
%USERPROFILE%\.venv\Scripts\pip install --upgrade PySimpleGUI
%USERPROFILE%\.venv\Scripts\pip install --upgrade Pillow
%USERPROFILE%\.venv\Scripts\pip install --upgrade bs4
%USERPROFILE%\.venv\Scripts\pip install --upgrade lxml
%USERPROFILE%\.venv\Scripts\pip install --upgrade mergedeep
%USERPROFILE%\.venv\Scripts\pip install --upgrade fuzzywuzzy
%USERPROFILE%\.venv\Scripts\pip install --upgrade dictdiffer
%USERPROFILE%\.venv\Scripts\pip install --upgrade termcolor
%USERPROFILE%\.venv\Scripts\pip install --upgrade pycryptodome
%USERPROFILE%\.venv\Scripts\pip install --upgrade pycryptodomex
%USERPROFILE%\.venv\Scripts\pip install --upgrade cryptography
%USERPROFILE%\.venv\Scripts\pip install --upgrade aenum
%USERPROFILE%\.venv\Scripts\pip install --upgrade fastxor
%USERPROFILE%\.venv\Scripts\pip install --upgrade packaging
%USERPROFILE%\.venv\Scripts\pip install --upgrade ecdsa
%USERPROFILE%\.venv\Scripts\pip install --upgrade schedule
%USERPROFILE%\.venv\Scripts\pip install --upgrade python-dateutil
%USERPROFILE%\.venv\Scripts\pip install --upgrade xxhash
%USERPROFILE%\.venv\Scripts\pip install --upgrade screeninfo
%USERPROFILE%\.venv\Scripts\pip install --upgrade tqdm
%USERPROFILE%\.venv\Scripts\pip install --upgrade pywin32
%USERPROFILE%\.venv\Scripts\pip install --upgrade pyuac
