# TryHackMe

## Windows

## Nmap

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.187.139 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-30 06:45 -04
Initiating SYN Stealth Scan at 06:45
Scanning 10.10.187.139 [65535 ports]
Discovered open port 8080/tcp on 10.10.187.139
Discovered open port 80/tcp on 10.10.187.139
Discovered open port 3389/tcp on 10.10.187.139
Completed SYN Stealth Scan at 06:46, 26.72s elapsed (65535 total ports)
Nmap scan report for 10.10.187.139
Host is up, received user-set (0.23s latency).
Scanned at 2025-06-30 06:45:49 -04 for 26s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
8080/tcp open  http-proxy    syn-ack ttl 127
```

