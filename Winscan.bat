@echo off
color 0f
::call:colorys调用底部:colorys
::02为颜色设置，0指定输出文字背景颜色，2指定文字颜色
::输出不能包含符号 / : ? * " > < | \
cd %~dp0
for /f "delims=" %%A in ('dir /s /b %WINDIR%\system32\*htable.xsl') do set "var=%%A"
if not exist ./eventlog/ (md eventlog)
if not exist ./schtasks/ (md schtasks)
if not exist ./Prefetch/ (md Prefetch)
if not exist ./hive/ (md hive)
if not exist ./CryptnetURLCache/ (md CryptnetURLCache)
if exist out.html (del out.html)
::reg query HKLM\SAM\SAM\Domains\Account\Users\Names
call:colorys 0A "[+] 正在查询系统相关信息："
@echo.
wmic OS get Caption,CSDVersion,OSArchitecture,Version
wmic computersystem list brief
call:colorys 0A "[+] 正在查询系统补丁情况，并写入文件："
wmic qfe get Description,HotFixID,InstalledOn /format:"%var%" >> out.html
@echo.
call:colorys 0A "[+] 正在查询系统账户和用户组，并写入文件："
@echo.
wmic UserAccount get name,description,sid,disabled
wmic UserAccount get Description,Disabled,LocalAccount,Lockout,Name,PasswordChangeable,PasswordExpires,PasswordRequired,SID,Status /format:"%var%" >> out.html
wmic group get Description,Domain,Name,SID,Status /format:"%var%" >> out.html
wmic volume get Label,DeviceID,DriveLetter,FileSystem,FreeSpace /format:"%var%" >> out.html
call:colorys 0A "[+] 正在检查域密码策略："
@echo.
Net accounts /domain
@echo.
call:colorys 0A "[+] 检查管理员组："
@echo.
net localgroup administrators
net group "domain admins" /domain
@echo.
call:colorys 0A "[+] 检查用户上次登录时间："
@echo.
wmic netlogin get name,lastlogon,badpasswordcount
call:colorys 0A "[+] 检查重要的注册表项："
@echo.
::SSP
reg query hklm\system\currentcontrolset\control\lsa /v "Security Packages"
::WDigest，1代表开启，0代表明文密码不会出现在内存中
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
@echo.
call:colorys 0A "[+] 检查RDP保存的凭证："
@echo.
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s > rdp_certificate.txt
call:colorys 0A "[+] 检查是否开启远程桌面服务："
::开启则返回0x00
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
call:colorys 0A "[+] 检查本机共享列表，并写入文件："
net share
Wmic share get name,path,status /format:"%var%" >> out.html
call:colorys 0A "[+] 检查系统启动信息，并写入文件："
@echo.
wmic startup get command,caption,Location,User
wmic startup get command,caption,Location,User /format:"%var%" >> out.html
@echo.
call:colorys 0A "[+] 检查已安装反病毒软件："
@echo.
wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState, pathToSignedProductExe
@echo.
call:colorys 0A "[+] 检查防火墙配置，并写入文件："
netsh firewall show config
netsh firewall show config > firewall_config.txt
@echo.
call:colorys 0A "[+] 检查Defender检测到的活动和过去的恶意软件威胁："
@echo.
powershell Get-MpThreatDetection
call:colorys 0A "[+] 正在拷贝防火墙日志和evtx："
@echo.
if exist %windir%\system32\logfiles\firewall\pfirewall.log (copy /Y %windir%\system32\logfiles\firewall\pfirewall.log)
copy /Y "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%%4Operational.evtx" .\eventlog\
@echo.
call:colorys 0A "[+] 检查已安装软件，并写入文件："
@echo.
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s /v DisplayName | findstr DisplayName
wmic PRODUCT get Description,InstallDate,InstallLocation,Vendor,Version /format:"%var%" >> out.html
@echo.
call:colorys 0A "[+] 检查计划任务，拷贝日志和计划任务文件"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
schtasks /query /fo LIST /v > .\schtasks\schtasks.txt
for %%i in (C:\Windows\System32\Tasks\*) do copy /Y %%i schtasks\
::for %%i in (C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskSche*) do copy /Y %%i schtasks\
copy /Y C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx .\eventlog\
copy /Y C:\Windows\System32\winevt\Logs\Microsoft-Windows-SMBServer%%4Security.evtx .\eventlog\
@echo.
call:colorys 0A "[+] 检查服务状态，并写入文件："
powershell Get-Service
powershell $aa="gwmi win32_service | ft -Property  Name, DisplayName, PathName, User, State > service.txt";$aa
wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:"%var%" >> out.html
call:colorys 0A "[+] 检查自启动服务："
@echo.
::RunSrvicese:win7、win10、2012
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\SOFTWARE\Microsoft\Windows\Currention\RunOnce
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceVers
@echo.
call:colorys 0A "[+] 检查自启动目录："
@echo.
dir /a "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir /a "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
dir /a "%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup"
@echo.
call:colorys 0A "[+] 检查注册表启动项，写入文件中："
@echo.
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\run >qidong.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce >>qidong.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >>qidong.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce >>qidong.txt
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run >>qidong.txt
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce >>qidong.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run >>qidong.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run >>qidong.txt
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartMenu >>qidong.txt
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v Load >>qidong.txt
@echo.
call:colorys 0A "[+] 检查网络连接（ipc$ 命名管道连接），并写入文件："
@echo.
net use
wmic netuse get ConnectionState,Description,DisplayType,LocalName,Name,Persistent,RemoteName,ResourceType,Status,UserName /format:"%var%" >> out.html
call:colorys 0A "[+] 检查是否启用Windows剪切板历史记录：(0x1代表启用，适用Win10）："
@echo.
reg query HKEY_CURRENT_USER\Software\Microsoft\Clipboard /v EnableClipboardHistory
@echo.
call:colorys 0A "[+] 检查用户登录初始化、管理员自动登录："
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
call:colorys 0A "[+] 检查Logon Scripts:"
reg query HKCU\Environment /v UserInitMprLogonScript
@echo.
call:colorys 0A "[+] 检查屏幕保护程序："
reg query "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE
@echo.
call:colorys 0A "[+] 检查AppInit_DLLs："
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
call:colorys 0A "[+] 检查COM劫持，并写入文件："
::通过修改注册表键值，使特定的clsid指向恶意的dll，程序运行时就会加载恶意的dll
reg query HKCU\Software\Classes\CLSID /s /t REG_SZ > 32os_32pe_and_64os_64pe.txt
reg query HKCU\Software\Classes\Wow6432Node\CLSID /s /t REG_SZ > x86OS_x64pe.txt
@echo.
call:colorys 0A "[+] 检查shim数据库是否被劫持："
@echo.
::主要解决应用兼容性问题的解决方法，执行被劫持的程序时自动加载数据库中恶意模块（dll，shellcode等）
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" /s
dir /a /b C:\Windows\AppPatch\Custom
dir /a /b C:\Windows\AppPatch\Custom\Custom64
@echo.
call:colorys 0A "[+] 检查进程注入："
@echo.
reg query "HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls"
@echo.
call:colorys 0A "[+] 检查exe文件启动相关注册表："
reg query HKLM\software\classes\exefile\shell\open\command
call:colorys 0A "[+] 检查Lsa，用于hash传递攻击："
reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin
call:colorys 0A "[+] 检查映像劫持："
rem 适用于windows 2008/win7
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -s -f ".exe" -v Debugger
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /f ".exe" /v GlobalFlag
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
@echo.
call:colorys 0A "[+] 查询接受最终用户许可协议的程序："
reg query HKCU\Software\SysInternals
@echo.
call:colorys 0A "[+] 查询安全模式启动相关注册表："
@echo.
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
call:colorys 0A "[+] 查询powershell命令记录，拷贝中："
@echo.
::适用于powershell高版本
if exist %appdata%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt type %appdata%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
copy /Y C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%%4Operational.evtx .\eventlog\
@echo.
call:colorys 0A "[+] 检查IE浏览器记录："
reg query "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"
call:colorys 0A "[+] 检查CryptnetURLCache，查看certutil下载记录："
::利用工具：CryptnetURLCacheParser
@echo.
if exist C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache (xcopy /s /q /h /o /y C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache .\CryptnetUrlCache\)
if exist C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache (xcopy /s /q /h /o /y C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache .\CryptnetUrlCache\)
if exist %USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache (xcopy /s /q /h /o /y %USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache .\CryptnetUrlCache\ )
@echo.
call:colorys 0A "[+] 检查最近访问的文件，写入文件中："
@echo.
dir /a %AppData%\Microsoft\Windows\Recent > Recent.txt
if exist "%SYSTEMROOT%\Documents and Settings\%USERPROFILE%\Recent\" (dir /a %SYSTEMROOT%\Documents and Settings\%USERPROFILE%\Recent\ >>Recent.txt)
dir /a %USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\ >>Recent.txt
@echo.
call:colorys 0A "[+] 检查"我的电脑、此电脑、计算机"的任意文件夹地址栏内的历史记录："
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
call:colorys 0A "[+] 检查【运行】的历史记录："
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
call:colorys 0A "[+] 检查网络连接情况，并写入文件："
@echo.
netstat -anob | findstr ESTABLISHED
::适用于Win10，Win7不适用
powershell $aa="Get-NetTCPConnection | select LocalAddress,localport,remoteaddress,remoteport,state,@{name=\"process\";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name=\"cmdline\";Expression={(Get-WmiObject Win32_Process -filter \"ProcessId = $($_.OwningProcess)\").commandline}} |  sort Remoteaddress -Descending | ft -wrap -autosize > network_tcp.txt";$aa
@echo.
call:colorys 0A "[+] 检查DNS缓存记录，并写入文件中："
::适用win10，win7不适用
@echo.
powershell $aa="Get-DnsClientCache |ft -wrap -autosize";$aa
ipconfig /displaydns > dns_cache.txt
call:colorys 0A "[+] 检查进程，写入文件中："
wmic process get name,ParentProcessId,processid,executablepath,CreationDate,commandline /format:"%var%" >> out.html
wmic process get name,parentprocessid,processid,executablepath,CreationDate,commandline /format:csv > process.csv
powershell $aa="gwmi win32_process | Select Name, ProcessID, @{n='Owner';e={$_.GetOwner().User}},CommandLine | ft -wrap -autosize > process_ps.txt";$aa
@echo.
call:colorys 0A "[+] 调查取证——导出SAM、SECURITY、SYSTEM（记录系统运行的可执行文件的完整路径和最后的执行日期）："
::可用Registry Explorer对SYSTEM文件进行分析，AppCompatCache记录程序的修改时间，一定程度上可以确定程序的最迟运行时间
@echo.
reg save hklm\system .\hive\SYSTEM /Y
reg save hklm\sam .\hive\SAM /Y
reg save hklm\security .\hive\SECURITY /Y
call:colorys 0A "[+] 调查取证——收集 Sysmon 日志："
if exist C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx (copy /Y "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx" .\eventlog\)
call:colorys 0A "[+] 调查取证——检查BAM（记录系统运行的可执行文件的完整路径和最后的执行日期，适用于Win10），写入文件中："
@echo.
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings" /s > BAM.txt
call:colorys 0A "[+] 调查取证——SRUM (System Resource Usage Monitor)，拷贝中："
if exist C:\Windows\System32\sru\SRUDB.dat (copy /Y C:\Windows\System32\sru\SRUDB.dat)
@echo.
call:colorys 0A "[+] 调查取证——MUICache (从exe文件的版本资源中提取应用程序名、公司名)，写入文件中："
reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" > MuiCache.txt
@echo.
call:colorys 0A "[+] 调查取证——ShimCache (跟踪文件路径、上次修改时间和是否被执行)，注册表导出中："
@echo.
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" ShimCache.reg /Y
call:colorys 0A "[+] 调查取证——Prefetch (会保存文件第一次和最后一次运行日期、路径和执行次数等信息)，拷贝中"
@echo.
::for %%i in (C:\Windows\Prefetch\*) do copy /Y %%i Prefetch\
xcopy /s /q /h /o /y C:\Windows\Prefetch .\Prefetch\
call:colorys 0A "[+] 检查系统日志是否有开启："
reg query HKLM\SYSTEM\CurrentControlSet\services\eventlog
call:colorys 0A "[+] 正在导出系统日志："
if exist .\eventlog\system.evtx (del .\eventlog\system.evtx)
wevtutil epl System .\eventlog\system.evtx
if exist .\eventlog\Application.evtx (del .\eventlog\Application.evtx)
wevtutil epl Application .\eventlog\Application.evtx
if exist .\eventlog\Security.evtx (del .\eventlog\Security.evtx)
wevtutil epl Security .\eventlog\Security.evtx
rem 远程桌面日志，筛选1149
if exist .\eventlog\TerminalServices.evtx (del .\eventlog\TerminalServices.evtx)
wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational .\eventlog\TerminalServices.evtx
@echo.
pause
::把以下代码放到批处理底部用call调用
:colorys
pushd %tmp%&echo CCAICCAI>%2-&certutil /f /decode %2- %2- 1>nul 2>nul
findstr /a:%1 . %2- \ 2>nul&del /q /f %2- 1>nul 2>nul&popd&exit /b
