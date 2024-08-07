- Telnet
- HTTP
- FTP
- SMTP
- POP3
- IMAP

Servers implementing these protocols are subject to different kinds of attacks. To name a few, consider:
1. Sniffing Attack (Network Packet Capture);
2. Man-in-the-Middle (MITM) Attack;
3. Password Attack (Authentication Attack);
4. Vulnerabilities.

From a security perspective, we always need to think about what we aim to protect; consider the security triad: Confidentiality, Integrity, and Availability (CIA):
- **Confidentiality** refers to keeping the contents of the communications accessible to the intended parties.
- **Integrity** is the idea of assuring any data sent is accurate, consistent, and complete when reaching its destination.
- **Availability** refers to being able to access the service when we need it.

![[Pasted image 20240803164332.png]]

Note:
	Different parties will put varying emphasis on these three. For instance, confidentiality would be the highest priority for an intelligence agency. Online banking will put most emphasis on the integrity of transactions. Availability is of the highest importance for any platform making money by serving ads.

These attacks directly affect the security of the system. For instance, network packet capture violates confidentiality and leads to the disclosure of information. A successful password attack can also lead to disclosure. On the other hand, a Man-in-the-Middle (MITM) attack breaks the system’s integrity as it can alter the communicated data.

Vulnerabilities are of a broader spectrum, and exploited vulnerabilities have different impacts on the target systems. For instance, exploiting a Denial of Service (DoS) vulnerability can affect the system’s availability, while exploiting a Remote Code Execution (RCE) vulnerability can lead to more severe damages. It is important to note that a vulnerability by itself creates a risk; damage can occur only when the vulnerability is exploited.

## Sniffing Attack
Sniffing attack refers to using a network packet capture tool to collect information about the target. When a protocol communicates in cleartext, the data exchanged can be captured by a third party to analyse. A simple network packet capture can reveal information, such as the content of private messages and login credentials, if the data isn't encrypted in transit.

A sniffing attack can be conducted using an Ethernet (802.3) network card, provided that the user has proper permissions (root permissions on Linux and administrator privileges on MS Windows). There are many programs available to capture network packets. We consider the following:
1. **Tcpdump** is a free open source command-line interface (CLI) program that has been ported to work on many operating systems.
2. **Wireshark** is a free open source graphical user interface (GUI) program available for several operating systems, including Linux, macOS and MS Windows.
3. **Tshark** is a CLI alternative to Wireshark.

Consider a user checking his email messages using POP3. First, we are going to use Tcpdump to attempt to capture the username and password. In the terminal output below, we used the command `sudo tcpdump port 110 -A`. This attack requires access to the network traffic, for example, via a wiretap or a switch with port mirroring. Alternatively, we can access the traffic exchanged if we launch a successful Man-in-the-Middle (MITM) attack.

We need `sudo` as packet captures require root privileges. We wanted to limit the number of captured and displayed packets to those exchanged with the POP3 server. We know that POP3 uses port 110, so we filtered our packets using `port 110`. Finally, we wanted to display the contents of the captured packets in ASCII format, so we added `-A`.
```shell-session
pentester@TryHackMe$ sudo tcpdump port 110 -A  !!!
[...]
09:05:15.132861 IP 10.20.30.1.58386 > 10.20.30.148.pop3: Flags [P.], seq 1:13, ack 19, win 502, options [nop,nop,TS val 423360697 ecr 3958275530], length 12
E..@.V@.@.g.
...
......n......"............
.;....}.USER frank

09:05:15.133465 IP 10.20.30.148.pop3 > 10.20.30.1.58386: Flags [.], ack 13, win 510, options [nop,nop,TS val 3958280553 ecr 423360697], length 0
E..4..@.@.O~
...
....n....".........?P.....
...i.;..
09:05:15.133610 IP 10.20.30.148.pop3 > 10.20.30.1.58386: Flags [P.], seq 19:43, ack 13, win 510, options [nop,nop,TS val 3958280553 ecr 423360697], length 24
E..L..@.@.Oe
...
....n....".........<-.....
...i.;..+OK Password required.

09:05:15.133660 IP 10.20.30.1.58386 > 10.20.30.148.pop3: Flags [.], ack 43, win 502, options [nop,nop,TS val 423360698 ecr 3958280553], length 0
E..4.W@.@.g.
...
......n......".....??.....
.;.....i
09:05:22.852695 IP 10.20.30.1.58386 > 10.20.30.148.pop3: Flags [P.], seq 13:28, ack 43, win 502, options [nop,nop,TS val 423368417 ecr 3958280553], length 15
E..C.X@.@.g.
...
......n......".....6......
.<.....iPASS D2xc9CgD
[...]
```

We could also use Wireshark to achieve the same results. In the Wireshark window below, we can see that we have entered `pop` in the filter field. Now that we've filtered just the traffic we're interested in, we can see a username and password were captured.
![[Pasted image 20240803154103.png]]

*Note:*
	In brief, any protocol that uses cleartext communication is susceptible to this kind of attack. The only requirement for this attack to succeed is to have access to a system between the two communicating systems. This attack requires attention; the mitigation lies in adding an encryption layer on top of any network protocol. In particular, Transport Layer Security (TLS) has been added to HTTP, FTP, SMTP, POP3, IMAP and many others. For remote access, Telnet has been replaced by the secure alternative Secure Shell (SSH).

## Man-in-the-Middle (MITM) Attack
A Man-in-the-Middle (MITM) attack occurs when a victim (A) believes they are communicating with a legitimate destination (B) but is unknowingly communicating with an attacker (E).

![[Pasted image 20240803154405.png]]

This attack is relatively simple to carry out if the two parties do not confirm the **authenticity** and **integrity** of each message. In some cases, the chosen protocol does not provide secure authentication or integrity checking; moreover, some protocols have inherent insecurities that make them susceptible to this kind of attack.

Any time you browse over HTTP, you are susceptible to a MITM attack, and the scary thing is that you cannot recognize it. Many tools would aid you in carrying out such an attack, such as [Ettercap](https://www.ettercap-project.org/) and [Bettercap](https://www.bettercap.org/).

*Note:*
	MITM can also affect other cleartext protocols such as FTP, SMTP, and POP3. Mitigation against this attack requires the use of cryptography. The solution lies in proper authentication along with encryption or signing of the exchanged messages. With the help of Public Key Infrastructure (PKI) and trusted root certificates, Transport Layer Security (TLS) protects from MITM attacks.

## Transport Layer Security (TLS)
A standard solution to protect the confidentiality and integrity of the exchanged packets. The following approach can protect against password sniffing and MITM attacks.
 
The common protocols we have covered so far send the data in cleartext; this makes it possible for anyone with access to the network to capture, save and analyze the exchanged messages. Consider the ISO/OSI model; we can add encryption to our protocols via the presentation layer. Consequently, data will be presented in an encrypted format (ciphertext) instead of its original form.
![[Pasted image 20240803164643.png]]

Because of the close relation between SSL and TLS, one might be used instead of the other. However, TLS is more secure than SSL, and it has practically replaced SSL. We could have dropped SSL and just written TLS instead of SSL/TLS, but we will continue to mention the two to avoid any ambiguity because the term SSL is still in wide use. However, we can expect all modern servers to be using TLS.

An existing cleartext protocol can be upgraded to use encryption via SSL/TLS. We can use TLS to upgrade HTTP, FTP, SMTP, POP3, and IMAP, to name a few. The following table lists the protocols we have covered and their default ports before and after the encryption upgrade via SSL/TLS.

| Protocol | Default Port | Secured Protocol | Default Port with TLS |
| -------- | ------------ | ---------------- | --------------------- |
| HTTP     | 80           | HTTPS            | 443                   |
| FTP      | 21           | FTPS             | 990                   |
| SMTP     | 25           | SMTPS            | 465                   |
| POP3     | 110          | POP3S            | 995                   |
| IMAP     | 143          | IMAPS            | 993                   |

Considering the case of HTTP. Initially, to retrieve a web page over HTTP, the web browser would need at least perform the following two steps:
1. Establish a TCP connection with the remote web server
2. Send HTTP requests to the web server, such as `GET` and `POST` requests.

HTTPS requires an additional step to encrypt the traffic. The new step takes place after establishing a TCP connection and before sending HTTP requests. This extra step can be inferred from the ISO/OSI model in the image presented earlier. Consequently, HTTPS requires at least the following three steps:
1. Establish a TCP connection
2. **Establish SSL/TLS connection**
3. Send HTTP requests to the webserver

To establish an SSL/TLS connection, the client needs to perform the proper handshake with the server. After establishing a TCP connection with the server, the client establishes an SSL/TLS connection, as shown in the figure below:
![[Pasted image 20240803165918.png]]
1. The client sends a `ClientHello` to the server to indicate its capabilities, such as supported algorithms.
2. The server responds with a `ServerHello`, indicating the selected connection parameters. The server provides its certificate if server authentication is required. The certificate is a digital file to identify itself; it is usually digitally signed by a third party. Moreover, it might send additional information necessary to generate the master key, in its `ServerKeyExchange` message, before sending the `ServerHelloDone` message to indicate that it is done with the negotiation.
3. The client responds with a `ClientKeyExchange`, which contains additional information required to generate the master key. Furthermore, it switches to use encryption and informs the server using the `ChangeCipherSpec` message.
4. The server switches to use encryption as well and informs the client in the `ChangeCipherSpec` message.

![[Pasted image 20240803175824.png]]


## Secure Shell (SSH)
Secure Shell (SSH) was created to provide a secure way for remote system administration. In other words, it lets you securely connect to another system over the network and execute commands on the remote system. Put simply, the “S” in SSH stands for secure, which can be summarized simply as:
1. You can confirm the identity of the remote server
2. Exchanged messages are encrypted and can only be decrypted by the intended recipient
3. Both sides can detect any modification in the messages

To use SSH, you need an SSH server and an SSH client. The SSH server listens on port 22 by default. The SSH client can authenticate using:
- A username and a password
- A private and public key (after the SSH server is configured to recognize the corresponding public key)

On Linux, macOS, and MS Windows builds after 2018, you can connect to an SSH server using the following command `ssh username@MACHINE_IP`.

```shell-session
user@TryHackMe$ ssh mark@MACHINE_IP  !!!
mark@MACHINE_IP's password: XBtc49AB  !!!

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 20 13:53:17 2021
mark@debian8:~$ 
```

*Note:*
	If this is the first time we connect to this system, we will need to confirm the fingerprint of the SSH server’s public key to avoid man-in-the-middle (MITM) attacks. In the case of SSH, we don’t usually have a third party to check if the public key is valid, so we need to do this manually. This attack is shown in the image below.

![[Pasted image 20240803180302.png]]

We can use SSH to transfer files using SCP (Secure Copy Protocol) based on the SSH protocol. An example of the syntax is as follows: `scp mark@MACHINE_IP:/home/mark/archive.tar.gz ~`.
	This command will copy a file named `archive.tar.gz` from the remote system located in the `/home/mark` directory to `~`, i.e., the root of the home directory of the currently logged-in user.

Another example syntax is `scp backup.tar.bz2 mark@MACHINE_IP:/home/mark/`. This command will copy the file `backup.tar.bz2` from the local system to the directory `/home/mark/` on the remote system.
```shell-session
user@TryHackMe$ scp document.txt mark@MACHINE_IP:/home/mark !!!
mark@MACHINE_IP's password:     !!!
document.txt                                        100% 1997KB  70.4MB/s   00:00
```

*Note:*
	FTP could be secured using SSL/TLS by using the FTPS protocol which uses port 990. It is worth mentioning that FTP can also be secured using the SSH protocol which is the SFTP protocol. By default this service listens on port 22, just like SSH.

## Password Attack
Authentication, or proving your identity, can be achieved through one of the following, or a combination of two:

1. Something you _know_, such as password and PIN code.
2. Something you _have_, such as a SIM card, RFID card, and USB dongle.
3. Something you _are_, such as fingerprint and iris.

Based on the 150 million usernames and passwords leaked from the Adobe breach in 2013, the top ten passwords are:
- 123456
- 123456789
- password
- adobe123
- 12345678
- qwerty
- 1234567
- 111111
- photoshop
- 123123

Attacks against passwords are usually carried out by:
1. **Password Guessing**: Guessing a password requires some knowledge of the target, such as their pet’s name and birth year.
2. **Dictionary Attack**: This approach expands on password guessing and attempts to include all valid words in a dictionary or a wordlist.
3. **Brute Force Attack**: This attack is the most exhaustive and time-consuming where an attacker can go as far as trying all possible character combinations, which grows fast (exponential growth with the number of characters).

Let’s focus on dictionary attacks. Over time, hackers have compiled list after list containing leaked passwords from data breaches. The choice of the word list should depend on your knowledge of the target. For instance, a French user might use a French word instead of an English one. Consequently, a French word list might be more promising.

We want an automated way to try the common passwords or the entries from a word list; here comes [THC Hydra](https://github.com/vanhauser-thc/thc-hydra). Hydra supports many protocols, including FTP, POP3, IMAP, SMTP, SSH, and all methods related to HTTP. The general command-line syntax is: `hydra -l username -P wordlist.txt server service` where we specify the following options:

- `-l username`: `-l` should precede the `username`, i.e. the login name of the target.
- `-P wordlist.txt`: `-P` precedes the `wordlist.txt` file, which is a text file containing the list of passwords you want to try with the provided username.
- `server` is the hostname or IP address of the target server.
- `service` indicates the service which you are trying to launch the dictionary attack.

Consider the following concrete examples:
- `hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.55.133 ftp` will use `mark` as the username as it iterates over the provided passwords against the FTP server.
- `hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://10.10.55.133` is identical to the previous example. `10.10.55.133 ftp` is the same as `ftp://10.10.55.133`.
- `hydra -l frank -P /usr/share/wordlists/rockyou.txt 10.10.55.133 ssh` will use `frank` as the user name as it tries to login via SSH using the different passwords.

There are some extra optional arguments that you can add:
- `-s PORT` to specify a non-default port for the service in question.
- `-V` or `-vV`, for verbose, makes Hydra show the username and password combinations that are being tried. This verbosity is very convenient to see the progress, especially if you are still not confident of your command-line syntax.
- `-t n` where n is the number of parallel connections to the target. `-t 16` will create 16 threads used to connect to the target.
- `-d`, for debugging, to get more detailed information about what’s going on. The debugging output can save you much frustration; for instance, if Hydra tries to connect to a closed port and timing out, `-d` will reveal this right away.


In summary, attacks against login systems can be carried out efficiently using a tool, such as THC Hydra combined with a suitable word list. Mitigation against such attacks can be sophisticated and depends on the target system. A few of the approaches include:

- Password Policy: Enforces minimum complexity constraints on the passwords set by the user.
- Account Lockout: Locks the account after a certain number of failed attempts.
- Throttling Authentication Attempts: Delays the response to a login attempt. A couple of seconds of delay is tolerable for someone who knows the password, but they can severely hinder automated tools.
- Using CAPTCHA: Requires solving a question difficult for machines. It works well if the login page is via a graphical user interface (GUI). (Note that CAPTCHA stands for Completely Automated Public Turing test to tell Computers and Humans Apart.)
- Requiring the use of a public certificate for authentication. This approach works well with SSH, for instance.
- Two-Factor Authentication: Ask the user to provide a code available via other means, such as email, smartphone app or SMS.
- There are many other approaches that are more sophisticated or might require some established knowledge about the user, such as IP-based geolocation.

![[Pasted image 20240803182625.png]]

## Summary

1. Sniffing Attack
2. MITM Attack
3. Password Attack

Many other attacks can be conducted against specific servers and protocols. We will provide a list of some related modules.
- [Vulnerability Research](https://tryhackme.com/module/vulnerability-research)
- [Metasploit](https://tryhackme.com/module/metasploit)
- [Burp Suite](https://tryhackme.com/module/learn-burp-suite)

| Protocol | TCP Port | Application(s)                  | Data Security |
| -------- | -------- | ------------------------------- | ------------- |
| FTP      | 21       | File Transfer                   | Cleartext     |
| FTPS     | 990      | File Transfer                   | Encrypted     |
| HTTP     | 80       | Worldwide Web                   | Cleartext     |
| HTTPS    | 443      | Worldwide Web                   | Encrypted     |
| IMAP     | 143      | Email (MDA)                     | Cleartext     |
| IMAPS    | 993      | Email (MDA)                     | Encrypted     |
| POP3     | 110      | Email (MDA)                     | Cleartext     |
| POP3S    | 995      | Email (MDA)                     | Encrypted     |
| SFTP     | 22       | File Transfer                   | Encrypted     |
| SSH      | 22       | Remote Access and File Transfer | Encrypted     |
| SMTP     | 25       | Email (MTA)                     | Cleartext     |
| SMTPS    | 465      | Email (MTA)                     | Encrypted     |
| Telnet   | 23       | Remote Access                   | Cleartext     |

Hydra remains a very efficient tool that you can launch from the terminal to try the different passwords. We summarize its main options in the following table.

|Option|Explanation|
|---|---|
|`-l username`|Provide the login name|
|`-P WordList.txt`|Specify the password list to use|
|`server service`|Set the server address and service to attack|
|`-s PORT`|Use in case of non-default service port number|
|`-V` or `-vV`|Show the username and password combinations being tried|
|`-d`|Display debugging output if the verbose output is not helping|