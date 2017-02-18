md bin32
copy build32\release\SyscallMonQT.exe bin32\SyscallMon.exe
G:\qt32\5.8\msvc2015\bin\windeployqt bin32\SyscallMon.exe
copy build32\SyscallMon32.sys bin32\
copy redist32\* bin32\
pause