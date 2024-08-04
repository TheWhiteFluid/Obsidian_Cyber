
What is the highest port number being open less than 10,000?
```
root@ip-10-10-153-80:~# nmap -T4 -p1-10000 -v --open 10.10.216.66  !!!

Starting Nmap 7.60 ( https://nmap.org ) at 2024-08-04 13:55 BST
Initiating ARP Ping Scan at 13:55
Scanning 10.10.216.66 [1 port]
Completed ARP Ping Scan at 13:55, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:55
Completed Parallel DNS resolution of 1 host. at 13:55, 0.00s elapsed
Initiating SYN Stealth Scan at 13:55
Scanning ip-10-10-216-66.eu-west-1.compute.internal (10.10.216.66) [10000 ports]
Discovered open port 22/tcp on 10.10.216.66
Discovered open port 80/tcp on 10.10.216.66
Discovered open port 8080/tcp on 10.10.216.66
Discovered open port 139/tcp on 10.10.216.66
Discovered open port 445/tcp on 10.10.216.66
Completed SYN Stealth Scan at 13:55, 10.83s elapsed (10000 total ports)
Nmap scan report for ip-10-10-216-66.eu-west-1.compute.internal (10.10.216.66)
Host is up (0.00061s latency).
Not shown: 9995 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy                 !!!
MAC Address: 02:A8:58:77:DE:AB (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.22 seconds
           Raw packets sent: 16595 (730.164KB) | Rcvd: 16595 (663.812KB)

```

There is an open port outside the common 1000 ports; it is above 10,000. What is it?
```
root@ip-10-10-153-80:~# nmap -T4 -p1-20000 -v --open 10.10.216.66   !!!

Starting Nmap 7.60 ( https://nmap.org ) at 2024-08-04 14:05 BST
Initiating ARP Ping Scan at 14:05
Scanning 10.10.216.66 [1 port]
Completed ARP Ping Scan at 14:05, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:05
Completed Parallel DNS resolution of 1 host. at 14:05, 0.00s elapsed
Initiating SYN Stealth Scan at 14:05
Scanning ip-10-10-216-66.eu-west-1.compute.internal (10.10.216.66) [20000 ports]
Discovered open port 445/tcp on 10.10.216.66
Discovered open port 139/tcp on 10.10.216.66
Discovered open port 22/tcp on 10.10.216.66
Discovered open port 80/tcp on 10.10.216.66
Discovered open port 8080/tcp on 10.10.216.66
Discovered open port 10021/tcp on 10.10.216.66
Completed SYN Stealth Scan at 14:05, 17.15s elapsed (20000 total ports)
Nmap scan report for ip-10-10-216-66.eu-west-1.compute.internal (10.10.216.66)
Host is up (0.00071s latency).
Not shown: 19994 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
8080/tcp  open  http-proxy
10021/tcp open  unknown    !!!
MAC Address: 02:A8:58:77:DE:AB (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.52 seconds
           Raw packets sent: 35608 (1.567MB) | Rcvd: 35608 (1.424MB)

```


What is the flag hidden in the HTTP server header?
```
root@ip-10-10-153-80:~# telnet 10.10.216.66 80  !!!
Trying 10.10.216.66...
Connected to 10.10.216.66.
Escape character is '^]'.
GET /index.html HTTP/1.1   !!!
host: telent    !!!

HTTP/1.1 200 OK
Vary: Accept-Encoding
Content-Type: text/html
Accept-Ranges: bytes
ETag: "229449419"
Last-Modified: Tue, 14 Sep 2021 07:33:09 GMT
Content-Length: 226
Date: Sun, 04 Aug 2024 13:07:30 GMT
Server: lighttpd THM{web_server_25352}   !!!

<!DOCTYPE html>
<html lang="en">
<head>
  <title>Hello, world!</title>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
</head>
<body>
  <h1>Hello, world!</h1>
</body>
</html>
Connection closed by foreign host.
```

What is the flag hidden in the SSH server header?
```
root@ip-10-10-153-80:~# telnet 10.10.216.66 22    !!!
Trying 10.10.216.66...
Connected to 10.10.216.66.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 THM{946219583339}    !!!

```

We have an FTP server listening on a nonstandard port. What is the version of the FTP server?
```
oot@ip-10-10-153-80:~# nmap -p10021 -sV -v 10.10.216.66   !!!

Starting Nmap 7.60 ( https://nmap.org ) at 2024-08-04 14:10 BST
NSE: Loaded 42 scripts for scanning.
Initiating ARP Ping Scan at 14:10
Scanning 10.10.216.66 [1 port]
Completed ARP Ping Scan at 14:10, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:10
Completed Parallel DNS resolution of 1 host. at 14:10, 0.00s elapsed
Initiating SYN Stealth Scan at 14:10
Scanning ip-10-10-216-66.eu-west-1.compute.internal (10.10.216.66) [1 port]
Discovered open port 10021/tcp on 10.10.216.66
Completed SYN Stealth Scan at 14:10, 0.22s elapsed (1 total ports)
Initiating Service scan at 14:10
Scanning 1 service on ip-10-10-216-66.eu-west-1.compute.internal (10.10.216.66)
Completed Service scan at 14:10, 0.01s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.216.66.
Initiating NSE at 14:10
Completed NSE at 14:10, 0.00s elapsed
Initiating NSE at 14:10
Completed NSE at 14:10, 0.00s elapsed
Nmap scan report for ip-10-10-216-66.eu-west-1.compute.internal (10.10.216.66)
Host is up (0.00015s latency).

PORT      STATE SERVICE VERSION
10021/tcp open  ftp     vsftpd 3.0.3   !!!
MAC Address: 02:A8:58:77:DE:AB (Unknown)
Service Info: OS: Unix

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds
           Raw packets sent: 3 (116B) | Rcvd: 3 (116B)

```

We learned two usernames using social engineering: `eddie` and `quinn`. What is the flag hidden in one of these two account files and accessible via FTP?
