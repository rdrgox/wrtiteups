# TryHackMe

Windows

## Nmap

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.187.139 -oG allPorts

PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
8080/tcp open  http-proxy    syn-ack ttl 127
```



