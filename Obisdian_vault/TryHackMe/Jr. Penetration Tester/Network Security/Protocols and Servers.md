Few protocols commonly used, such as:
- Telnet
- HTTP
- FTP
- POP3
- SMTP
- IMAP

## Telnet
The Telnet protocol is an application layer protocol used to connect to a virtual terminal of another computer. Using Telnet, a user can log into another computer and access its terminal (console) to run programs, start batch processes, and perform system administration tasks remotely.

When a user connects, they will be asked for a username and password. Upon correct authentication, the user will access the remote system’s terminal. Unfortunately, all this communication between the Telnet client and the Telnet server is not encrypted, making it an easy target for attackers.

A Telnet server uses the Telnet protocol to listen for incoming connections on port 23.
```shell-session
pentester@TryHackMe$ telnet MACHINE_IP
Trying MACHINE_IP...
Connected to MACHINE_IP.
Escape character is '^]'.
Ubuntu 20.04.3 LTS
bento login: frank
Password: D2xc9CgD
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 01 Oct 2021 12:24:56 PM UTC

  System load:  0.05              Processes:              243
  Usage of /:   45.7% of 6.53GB   Users logged in:        1
  Memory usage: 15%               IPv4 address for ens33: MACHINE_IP
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


*** System restart required ***
Last login: Fri Oct  1 12:17:25 UTC 2021 from meiyo on pts/3
You have mail.
frank@bento:~$
```

Telnet is not a reliable protocol for remote administration as all the data are sent in cleartext. The figure below shows the ASCII data exchanged between our computer and the remote system. The text in red is the text that we are sending to the remote system, while the text in blue is the text that the remote system is sending.
![[Pasted image 20240802165501.png]]

*Note:*
	Telnet is no longer considered a secure option, especially that anyone capturing your network traffic will be able to discover your usernames and passwords, which would grant them access to the remote system. The secure alternative is SSH.

## Hypertext Transfer Protocol (HTTP)
Hypertext Transfer Protocol (HTTP) is the protocol used to transfer web pages. Web browser connects to the webserver and uses HTTP to request HTML pages and images among other files and submit forms and upload various files.

![[Pasted image 20240802171439.png]]

HTTP sends and receives data as cleartext (not encrypted); therefore, you can use a simple tool, such as Telnet (or Netcat), to communicate with a web server and act as a “web browser”. 

*Note:*
	The key difference is that you need to input the HTTP-related commands instead of the web browser doing that for you.

In the following example, we will see how we can request a page from a web server. To accomplish this, we will use the Telnet client. We chose it because Telnet is a simple protocol; furthermore, it uses cleartext for communication. We will use `telnet` instead of a web browser to request a file from the webserver. The steps will be as follows:

1. First, we connect to port 80 using `telnet MACHINE_IP 80`.
2. Next, we need to type `GET /index.html HTTP/1.1` to retrieve the page `index.html` or `GET / HTTP/1.1` to retrieve the default page.
3. Finally, you need to provide some value for the host like `host: telnet` and press the Enter/Return key **twice**.

```shell-session
pentester@TryHackMe$ telnet MACHINE_IP 80
Trying MACHINE_IP...
Connected to MACHINE_IP.
Escape character is '^]'.
GET /index.html HTTP/1.1
host: telnet

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 15 Sep 2021 08:56:20 GMT
Content-Type: text/html
Content-Length: 234
Last-Modified: Wed, 15 Sep 2021 08:53:59 GMT
Connection: keep-alive
ETag: "6141b4a7-ea"
Accept-Ranges: bytes

<!DOCTYPE html>
<html lang="en">
<head>
  <title>Welcome to my Web Server</title>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
</head>
<body>
  <h1>Coming Soon<h1>
</body>
</html>
```

*Note:*
	We need an HTTP server (webserver) and an HTTP client (web browser) to use the HTTP protocol. The web server will “serve” a specific set of files to the requesting web browser.

Three popular choices for HTTP servers are:
- [Apache](https://www.apache.org/)
- [nginx](https://nginx.org/)  
- [Internet Information Services (IIS)](https://www.iis.net/)
```
root@ip-10-10-232-50:~# telnet 10.10.179.8 80
Trying 10.10.179.8...
Connected to 10.10.179.8.
Escape character is '^]'.
GET /flag.thm HTTP/1.1
host:telnet

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 02 Aug 2024 15:01:24 GMT
Content-Type: application/octet-stream
Content-Length: 39
Last-Modified: Wed, 15 Sep 2021 09:19:23 GMT
Connection: keep-alive
ETag: "6141ba9b-27"
Accept-Ranges: bytes

THM{e3eb0a1df437f3f97a64aca5952c8ea0}
```

## File Transfer Protocol (FTP)
File Transfer Protocol (FTP) was developed to make the transfer of files between different computers with different systems efficient.

FTP also sends and receives data as cleartext; therefore, we can use Telnet (or Netcat) to communicate with an FTP server and act as an FTP client. In the example below, we carried out the following steps:
1. We connected to an FTP server using a Telnet client. Since FTP servers listen on port 21 by default, we had to specify to our Telnet client to attempt connection to port 21 instead of the default Telnet port.
2. We needed to provide the username with the command `USER frank`.
3. Then, we provided the password with the command `PASS D2xc9CgD`.
4. Because we supplied the correct username and password, we got logged in.

*Note:*
- The `SYST` command shows the System Type of the target (UNIX in this case). 
- A command like `STAT` can provide some added information
- `PASV` switches the mode to passive. It is worth noting that there are two modes for FTP:
	 *`Active`*: In the active mode, the data is sent over a separate channel originating from the FTP server’s port 20.
	 *`Passive`*: In the passive mode, the data is sent over a separate channel originating from an FTP client’s port above port number 1023.