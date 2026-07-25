@echo off
REM Build a standalone, self-contained nullsec.exe (bundled icon + data + libs).
REM The build recipe lives in nullsec.spec so the .bat and CI stay in sync.
echo Building nullsec.exe ...
pip install "pyinstaller>=6.0"
pyinstaller nullsec.spec --clean --noconfirm
echo.
echo Done. exe is in dist\nullsec.exe
