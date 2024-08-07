
What is the highest port number being open less than 10,000?
```
root@ip-10-10-14-207:~# nmap -T4 -p1-10000 --open -v  10.10.165.16   !!!

Starting Nmap 7.60 ( https://nmap.org ) at 2024-08-03 21:14 BST
Initiating ARP Ping Scan at 21:14
Scanning 10.10.165.16 [1 port]
Completed ARP Ping Scan at 21:14, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:14
Completed Parallel DNS resolution of 1 host. at 21:14, 0.00s elapsed
Initiating SYN Stealth Scan at 21:14
Scanning ip-10-10-165-16.eu-west-1.compute.internal (10.10.165.16) [10000 ports]
Discovered open port 22/tcp on 10.10.165.16
Discovered open port 139/tcp on 10.10.165.16
Discovered open port 445/tcp on 10.10.165.16
Discovered open port 80/tcp on 10.10.165.16
Discovered open port 8080/tcp on 10.10.165.16
Completed SYN Stealth Scan at 21:14, 9.00s elapsed (10000 total ports)
Nmap scan report for ip-10-10-165-16.eu-west-1.compute.internal (10.10.165.16)
Host is up (0.00050s latency).
Not shown: 9995 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy
MAC Address: 02:D3:DB:82:8A:17 (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 9.37 seconds
           Raw packets sent: 17262 (759.512KB) | Rcvd: 17262 (690.488KB)
```


There is an open port outside the common 1000 ports; it is above 10,000. What is it?
```
root@ip-10-10-14-207:~# nmap -T4 -p1-20000 --open -v  10.10.165.16

Starting Nmap 7.60 ( https://nmap.org ) at 2024-08-03 21:28 BST
Initiating ARP Ping Scan at 21:28
Scanning 10.10.165.16 [1 port]
Completed ARP Ping Scan at 21:28, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:28
Completed Parallel DNS resolution of 1 host. at 21:28, 0.00s elapsed
Initiating SYN Stealth Scan at 21:28
Scanning ip-10-10-165-16.eu-west-1.compute.internal (10.10.165.16) [20000 ports]
Discovered open port 139/tcp on 10.10.165.16
Discovered open port 22/tcp on 10.10.165.16
Discovered open port 8080/tcp on 10.10.165.16
Discovered open port 445/tcp on 10.10.165.16
Discovered open port 80/tcp on 10.10.165.16
Discovered open port 10021/tcp on 10.10.165.16
```


What is the flag hidden in the HTTP server header?
```
root@ip-10-10-14-207:~# telnet 10.10.165.16 80  !!!
Trying 10.10.165.16...
Connected to 10.10.165.16.
Escape character is '^]'.
GET /index.html HTTP/1.1    !!!
host: telnet   !!!

HTTP/1.1 200 OK
Vary: Accept-Encoding
Content-Type: text/html
Accept-Ranges: bytes
ETag: "229449419"
Last-Modified: Tue, 14 Sep 2021 07:33:09 GMT
Content-Length: 226
Date: Sat, 03 Aug 2024 20:35:10 GMT
Server: lighttpd THM{web_server_25352}  !!!

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
```


What is the flag hidden in the SSH server header?
```
root@ip-10-10-14-207:~# telnet 10.10.165.16 22   !!!
Trying 10.10.165.16...
Connected to 10.10.165.16.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 THM{946219583339}    !!!
```


We have an FTP server listening on a nonstandard port. What is the version of the FTP server?
```
root@ip-10-10-14-207:~# nmap -sV -p10021 10.10.165.16    !!!

Starting Nmap 7.60 ( https://nmap.org ) at 2024-08-03 21:42 BST
Nmap scan report for ip-10-10-165-16.eu-west-1.compute.internal (10.10.165.16)
Host is up (0.00014s latency).

PORT      STATE SERVICE VERSION
10021/tcp open  ftp     vsftpd 3.0.3      !!!
MAC Address: 02:D3:DB:82:8A:17 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.01 seconds
```


We learned two usernames using social engineering: `eddie` and `quinn`. What is the flag hidden in one of these two account files and accessible via FTP?
