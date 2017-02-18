md bin64
copy build64\release\SyscallMonQT.exe bin64\SyscallMon.exe
G:\qt\5.7\msvc2015_64\bin\windeployqt bin64\SyscallMon.exe
copy build64\SyscallMon64.sys bin64\
copy redist64\* bin64\
pause