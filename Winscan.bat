@echo off
color 0f
::call:colorys���õײ�:colorys
::02Ϊ��ɫ���ã�0ָ��������ֱ�����ɫ��2ָ��������ɫ
::������ܰ������� / : ? * " > < | \
cd %~dp0
for /f "delims=" %%A in ('dir /s /b %WINDIR%\system32\*htable.xsl') do set "var=%%A"
if not exist ./eventlog/ (md eventlog)
if not exist ./schtasks/ (md schtasks)
if not exist ./Prefetch/ (md Prefetch)
if not exist ./hive/ (md hive)
if not exist ./CryptnetURLCache/ (md CryptnetURLCache)
if exist out.html (del out.html)
::reg query HKLM\SAM\SAM\Domains\Account\Users\Names
call:colorys 0A "[+] ���ڲ�ѯϵͳ�����Ϣ��"
@echo.
wmic OS get Caption,CSDVersion,OSArchitecture,Version
wmic computersystem list brief
call:colorys 0A "[+] ���ڲ�ѯϵͳ�����������д���ļ���"
wmic qfe get Description,HotFixID,InstalledOn /format:"%var%" >> out.html
@echo.
call:colorys 0A "[+] ���ڲ�ѯϵͳ�˻����û��飬��д���ļ���"
@echo.
wmic UserAccount get name,description,sid,disabled
wmic UserAccount get Description,Disabled,LocalAccount,Lockout,Name,PasswordChangeable,PasswordExpires,PasswordRequired,SID,Status /format:"%var%" >> out.html
wmic group get Description,Domain,Name,SID,Status /format:"%var%" >> out.html
wmic volume get Label,DeviceID,DriveLetter,FileSystem,FreeSpace /format:"%var%" >> out.html
call:colorys 0A "[+] ���ڼ����������ԣ�"
@echo.
Net accounts /domain
@echo.
call:colorys 0A "[+] ������Ա�飺"
@echo.
net localgroup administrators
net group "domain admins" /domain
@echo.
call:colorys 0A "[+] ����û��ϴε�¼ʱ�䣺"
@echo.
wmic netlogin get name,lastlogon,badpasswordcount
call:colorys 0A "[+] �����Ҫ��ע����"
@echo.
::SSP
reg query hklm\system\currentcontrolset\control\lsa /v "Security Packages"
::WDigest��1��������0�����������벻��������ڴ���
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
@echo.
call:colorys 0A "[+] ���RDP�����ƾ֤��"
@echo.
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s > rdp_certificate.txt
call:colorys 0A "[+] ����Ƿ���Զ���������"
::�����򷵻�0x00
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
call:colorys 0A "[+] ��鱾�������б���д���ļ���"
net share
Wmic share get name,path,status /format:"%var%" >> out.html
call:colorys 0A "[+] ���ϵͳ������Ϣ����д���ļ���"
@echo.
wmic startup get command,caption,Location,User
wmic startup get command,caption,Location,User /format:"%var%" >> out.html
@echo.
call:colorys 0A "[+] ����Ѱ�װ�����������"
@echo.
wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState, pathToSignedProductExe
@echo.
call:colorys 0A "[+] ������ǽ���ã���д���ļ���"
netsh firewall show config
netsh firewall show config > firewall_config.txt
@echo.
call:colorys 0A "[+] ���Defender��⵽�Ļ�͹�ȥ�Ķ��������в��"
@echo.
powershell Get-MpThreatDetection
call:colorys 0A "[+] ���ڿ�������ǽ��־��evtx��"
@echo.
if exist %windir%\system32\logfiles\firewall\pfirewall.log (copy /Y %windir%\system32\logfiles\firewall\pfirewall.log)
copy /Y "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%%4Operational.evtx" .\eventlog\
@echo.
call:colorys 0A "[+] ����Ѱ�װ�������д���ļ���"
@echo.
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s /v DisplayName | findstr DisplayName
wmic PRODUCT get Description,InstallDate,InstallLocation,Vendor,Version /format:"%var%" >> out.html
@echo.
call:colorys 0A "[+] ���ƻ����񣬿�����־�ͼƻ������ļ�"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
schtasks /query /fo LIST /v > .\schtasks\schtasks.txt
for %%i in (C:\Windows\System32\Tasks\*) do copy /Y %%i schtasks\
::for %%i in (C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskSche*) do copy /Y %%i schtasks\
copy /Y C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx .\eventlog\
copy /Y C:\Windows\System32\winevt\Logs\Microsoft-Windows-SMBServer%%4Security.evtx .\eventlog\
@echo.
call:colorys 0A "[+] ������״̬����д���ļ���"
powershell Get-Service
powershell $aa="gwmi win32_service | ft -Property  Name, DisplayName, PathName, User, State > service.txt";$aa
wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:"%var%" >> out.html
call:colorys 0A "[+] �������������"
@echo.
::RunSrvicese:win7��win10��2012
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\SOFTWARE\Microsoft\Windows\Currention\RunOnce
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceVers
@echo.
call:colorys 0A "[+] ���������Ŀ¼��"
@echo.
dir /a "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir /a "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
dir /a "%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup"
@echo.
call:colorys 0A "[+] ���ע��������д���ļ��У�"
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
call:colorys 0A "[+] ����������ӣ�ipc$ �����ܵ����ӣ�����д���ļ���"
@echo.
net use
wmic netuse get ConnectionState,Description,DisplayType,LocalName,Name,Persistent,RemoteName,ResourceType,Status,UserName /format:"%var%" >> out.html
call:colorys 0A "[+] ����Ƿ�����Windows���а���ʷ��¼��(0x1�������ã�����Win10����"
@echo.
reg query HKEY_CURRENT_USER\Software\Microsoft\Clipboard /v EnableClipboardHistory
@echo.
call:colorys 0A "[+] ����û���¼��ʼ��������Ա�Զ���¼��"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
call:colorys 0A "[+] ���Logon Scripts:"
reg query HKCU\Environment /v UserInitMprLogonScript
@echo.
call:colorys 0A "[+] �����Ļ��������"
reg query "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE
@echo.
call:colorys 0A "[+] ���AppInit_DLLs��"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
call:colorys 0A "[+] ���COM�ٳ֣���д���ļ���"
::ͨ���޸�ע����ֵ��ʹ�ض���clsidָ������dll����������ʱ�ͻ���ض����dll
reg query HKCU\Software\Classes\CLSID /s /t REG_SZ > 32os_32pe_and_64os_64pe.txt
reg query HKCU\Software\Classes\Wow6432Node\CLSID /s /t REG_SZ > x86OS_x64pe.txt
@echo.
call:colorys 0A "[+] ���shim���ݿ��Ƿ񱻽ٳ֣�"
@echo.
::��Ҫ���Ӧ�ü���������Ľ��������ִ�б��ٳֵĳ���ʱ�Զ��������ݿ��ж���ģ�飨dll��shellcode�ȣ�
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" /s
dir /a /b C:\Windows\AppPatch\Custom
dir /a /b C:\Windows\AppPatch\Custom\Custom64
@echo.
call:colorys 0A "[+] ������ע�룺"
@echo.
reg query "HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls"
@echo.
call:colorys 0A "[+] ���exe�ļ��������ע���"
reg query HKLM\software\classes\exefile\shell\open\command
call:colorys 0A "[+] ���Lsa������hash���ݹ�����"
reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin
call:colorys 0A "[+] ���ӳ��ٳ֣�"
rem ������windows 2008/win7
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -s -f ".exe" -v Debugger
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /f ".exe" /v GlobalFlag
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
@echo.
call:colorys 0A "[+] ��ѯ���������û����Э��ĳ���"
reg query HKCU\Software\SysInternals
@echo.
call:colorys 0A "[+] ��ѯ��ȫģʽ�������ע���"
@echo.
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
call:colorys 0A "[+] ��ѯpowershell�����¼�������У�"
@echo.
::������powershell�߰汾
if exist %appdata%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt type %appdata%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
copy /Y C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%%4Operational.evtx .\eventlog\
@echo.
call:colorys 0A "[+] ���IE�������¼��"
reg query "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs"
call:colorys 0A "[+] ���CryptnetURLCache���鿴certutil���ؼ�¼��"
::���ù��ߣ�CryptnetURLCacheParser
@echo.
if exist C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache (xcopy /s /q /h /o /y C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache .\CryptnetUrlCache\)
if exist C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache (xcopy /s /q /h /o /y C:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache .\CryptnetUrlCache\)
if exist %USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache (xcopy /s /q /h /o /y %USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache .\CryptnetUrlCache\ )
@echo.
call:colorys 0A "[+] ���������ʵ��ļ���д���ļ��У�"
@echo.
dir /a %AppData%\Microsoft\Windows\Recent > Recent.txt
if exist "%SYSTEMROOT%\Documents and Settings\%USERPROFILE%\Recent\" (dir /a %SYSTEMROOT%\Documents and Settings\%USERPROFILE%\Recent\ >>Recent.txt)
dir /a %USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\ >>Recent.txt
@echo.
call:colorys 0A "[+] ���"�ҵĵ��ԡ��˵��ԡ������"�������ļ��е�ַ���ڵ���ʷ��¼��"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
call:colorys 0A "[+] ��顾���С�����ʷ��¼��"
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
call:colorys 0A "[+] ������������������д���ļ���"
@echo.
netstat -anob | findstr ESTABLISHED
::������Win10��Win7������
powershell $aa="Get-NetTCPConnection | select LocalAddress,localport,remoteaddress,remoteport,state,@{name=\"process\";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name=\"cmdline\";Expression={(Get-WmiObject Win32_Process -filter \"ProcessId = $($_.OwningProcess)\").commandline}} |  sort Remoteaddress -Descending | ft -wrap -autosize > network_tcp.txt";$aa
@echo.
call:colorys 0A "[+] ���DNS�����¼����д���ļ��У�"
::����win10��win7������
@echo.
powershell $aa="Get-DnsClientCache |ft -wrap -autosize";$aa
ipconfig /displaydns > dns_cache.txt
call:colorys 0A "[+] �����̣�д���ļ��У�"
wmic process get name,ParentProcessId,processid,executablepath,CreationDate,commandline /format:"%var%" >> out.html
wmic process get name,parentprocessid,processid,executablepath,CreationDate,commandline /format:csv > process.csv
powershell $aa="gwmi win32_process | Select Name, ProcessID, @{n='Owner';e={$_.GetOwner().User}},CommandLine | ft -wrap -autosize > process_ps.txt";$aa
@echo.
call:colorys 0A "[+] ����ȡ֤��������SAM��SECURITY��SYSTEM����¼ϵͳ���еĿ�ִ���ļ�������·��������ִ�����ڣ���"
::����Registry Explorer��SYSTEM�ļ����з�����AppCompatCache��¼������޸�ʱ�䣬һ���̶��Ͽ���ȷ��������������ʱ��
@echo.
reg save hklm\system .\hive\SYSTEM /Y
reg save hklm\sam .\hive\SAM /Y
reg save hklm\security .\hive\SECURITY /Y
call:colorys 0A "[+] ����ȡ֤�����ռ� Sysmon ��־��"
if exist C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx (copy /Y "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx" .\eventlog\)
call:colorys 0A "[+] ����ȡ֤�������BAM����¼ϵͳ���еĿ�ִ���ļ�������·��������ִ�����ڣ�������Win10����д���ļ��У�"
@echo.
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings" /s > BAM.txt
call:colorys 0A "[+] ����ȡ֤����SRUM (System Resource Usage Monitor)�������У�"
if exist C:\Windows\System32\sru\SRUDB.dat (copy /Y C:\Windows\System32\sru\SRUDB.dat)
@echo.
call:colorys 0A "[+] ����ȡ֤����MUICache (��exe�ļ��İ汾��Դ����ȡӦ�ó���������˾��)��д���ļ��У�"
reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" > MuiCache.txt
@echo.
call:colorys 0A "[+] ����ȡ֤����ShimCache (�����ļ�·�����ϴ��޸�ʱ����Ƿ�ִ��)��ע������У�"
@echo.
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" ShimCache.reg /Y
call:colorys 0A "[+] ����ȡ֤����Prefetch (�ᱣ���ļ���һ�κ����һ���������ڡ�·����ִ�д�������Ϣ)��������"
@echo.
::for %%i in (C:\Windows\Prefetch\*) do copy /Y %%i Prefetch\
xcopy /s /q /h /o /y C:\Windows\Prefetch .\Prefetch\
call:colorys 0A "[+] ���ϵͳ��־�Ƿ��п�����"
reg query HKLM\SYSTEM\CurrentControlSet\services\eventlog
call:colorys 0A "[+] ���ڵ���ϵͳ��־��"
if exist .\eventlog\system.evtx (del .\eventlog\system.evtx)
wevtutil epl System .\eventlog\system.evtx
if exist .\eventlog\Application.evtx (del .\eventlog\Application.evtx)
wevtutil epl Application .\eventlog\Application.evtx
if exist .\eventlog\Security.evtx (del .\eventlog\Security.evtx)
wevtutil epl Security .\eventlog\Security.evtx
rem Զ��������־��ɸѡ1149
if exist .\eventlog\TerminalServices.evtx (del .\eventlog\TerminalServices.evtx)
wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational .\eventlog\TerminalServices.evtx
@echo.
pause
::�����´���ŵ�������ײ���call����
:colorys
pushd %tmp%&echo CCAICCAI>%2-&certutil /f /decode %2- %2- 1>nul 2>nul
findstr /a:%1 . %2- \ 2>nul&del /q /f %2- 1>nul 2>nul&popd&exit /b
