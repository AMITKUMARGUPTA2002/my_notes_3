
# single port 

 ```
 chisel server -p 8001 --reverse
```

```
chisel client 192.168.45.244:8001 R:8000:127.0.0.1:8000
```


# Nmap proxychain
```
proxychains -q nmap -n -Pn -F -sV -sT -oA nmap_results -vvv -iL targets.txt -T4 --max-retries 1 --max-rtt-timeout 2s --ttl 50ms --open
```

```
proxychains -q nmap -n -Pn -F -sV -sT -oA nmap_results -vvv -T4 --max-retries 1 --max-rtt-timeout 2s --ttl 50ms --open 10.4.125.215
```

# Dynamic port forwarding

```
chisel server -p 8000 --reverse
```

```
chisel client 192.168.45.159:8000 R:9999:socks
```

# port scan
```
seq 1 65535 | xargs -P50 -I{} proxychains -q nc -z -v -w 1 172.16.189.217 {} 2>&1  | grep -v -iE 'refused|timed'
```

# double port forwarding
### On our local Kali:

`./chisel_linux server --socks5 -p 9001 --reverse`

/etc/proxychains

`socks5 127.0.0.1 9999 socks5 127.0.0.1 8888`

DMZ01:

`./chisel_linux client 10.10.14.227:9001 R:9999:socks
./chisel_linux server  -p 9002 --reverse --socks5` 

DC01:

`chisel.exe client 172.16.8.120:9002 R:8888:socks`

Now close any Socks4 connection (e.g. SSH Dynamic Port Forward) and comment in /etc/proxychains

# configuration
_make sure to change the_ `/etc/proxychains4.conf ` file

```php
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 9998
```

