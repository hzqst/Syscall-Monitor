Syscall Monitor
==============

Introduction
-------------
This is a process monitoring tool (like Sysinternal's Process Monitor) implemented with Intel VT-X/EPT for Windows 7+.

Deployment
-------------
- QT GUI project: SyscallMonQT/SyscallMonQT.pro
- Windows kernel driver project: ddimon/DdiMon/DdiMon.vcxproj
- Remember to modify the shadow build path to /build32 or /build64 when configure the QT project
- Remember to modify the windeploy.exe path in deploy32/deploy64.bat, run deploy32/64.bat to deploy x86/x64 binary files to bin32/bin64
- Remember to sign the x64 kernel driver file

Platform
--------------------
- x86 and x64 Windows 7, 8.1 and 10
- CPU with Intel VT-x and EPT technology support

Reference & Thanks
--------------------
- BOOST http://www.boost.org/
- QT https://www.qt.io/
- HyperPlatform https://github.com/tandasat/HyperPlatform