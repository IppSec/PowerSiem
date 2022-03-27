This script is a proof of concept to tail the Sysmon Event Log. I primarily use it to create (and validate) IOC's for malware.  I created it on stream here: https://www.twitch.tv/videos/1438252177

Example:

```
Type: File Create
RecordID: 2836
TargetFilename: C:\Windows\SBvrixHw.exe
Process: System
PID: 4
User: NT AUTHORITY\SYSTEM
-----
Type: Process Create
Image: C:\Windows\SBvrixHw.exe
ParentCommandLine: C:\WINDOWS\system32\services.exe
ParentUser: NT AUTHORITY\SYSTEM
CurrentDirectory: C:\WINDOWS\system32\
CommandLine: C:\WINDOWS\SBvrixHw.exe
ParentImage: C:\Windows\System32\services.exe
PID: 4680
User: NT AUTHORITY\SYSTEM
-----
Type: Process Create
Image: C:\Windows\SysWOW64\cmd.exe
ParentCommandLine: C:\WINDOWS\SBvrixHw.exe
ParentUser: NT AUTHORITY\SYSTEM
CurrentDirectory: C:\WINDOWS\system32\
CommandLine: cmd.exe
ParentImage: C:\Windows\SBvrixHw.exe
PID: 7336
User: NT AUTHORITY\SYSTEM
-----
Type: Process Create
Image: C:\Windows\SysWOW64\whoami.exe
ParentCommandLine: cmd.exe
ParentUser: NT AUTHORITY\SYSTEM
CurrentDirectory: C:\WINDOWS\system32\
CommandLine: whoami
ParentImage: C:\Windows\SysWOW64\cmd.exe
PID: 6712
User: NT AUTHORITY\SYSTEM
-----
Type: File Delete
RecordID: 2855
TargetFilename: C:\Windows\SBvrixHw.exe
Process: System
PID: 4
User: NT AUTHORITY\SYSTEM
-----
```
