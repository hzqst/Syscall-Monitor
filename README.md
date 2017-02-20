Syscall Monitor
==============

Introduction
-------------
This is a process monitoring tool (like Sysinternal's Process Monitor) implemented with Intel VT-X/EPT for Windows 7+.

Develop Environment
-------------
- Visual Studio 2015 update 3
- Windows SDK 10
- Windows Driver Kit 10
- QT5.7 for MSVC

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
- Capstone http://www.capstone-engine.org/

TODO
--------------------
1.Optimize the memory usage issue.

Screenshots
--------------------
![load symbol](https://github.com/hzqst/Syscall-Monitor/blob/master/snaps/1.png?raw=true)
![main frame](https://github.com/hzqst/Syscall-Monitor/blob/master/snaps/2.png?raw=true)
![process view](https://github.com/hzqst/Syscall-Monitor/blob/master/snaps/3.png?raw=true)
![event info](https://github.com/hzqst/Syscall-Monitor/blob/master/snaps/4.png?raw=true)
![event filter](https://github.com/hzqst/Syscall-Monitor/blob/master/snaps/5.png?raw=true)
![filtered](https://github.com/hzqst/Syscall-Monitor/blob/master/snaps/6.png?raw=true)
![filterable attributes](https://github.com/hzqst/Syscall-Monitor/blob/master/snaps/7.png?raw=true)
![process info](https://github.com/hzqst/Syscall-Monitor/blob/master/snaps/8.png?raw=true)