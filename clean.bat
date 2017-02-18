@echo off

del *.sdf

del *.VC.db

del /s *.aps

del /a:h *.suo

rmdir /s /q .vs

rmdir /s /q ipch

rmdir /s /q x64

rmdir /s /q Debug

rmdir /s /q Release

rmdir /s /q DdiMon\HyperPlatform\x64

rmdir /s /q DdiMon\HyperPlatform\Debug

rmdir /s /q DdiMon\HyperPlatform\Release

rmdir /s /q doxygen


del /s /q "bin32"

del /s /q "bin64"

pause