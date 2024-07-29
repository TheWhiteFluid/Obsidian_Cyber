
![[Pasted image 20240728034725.png]]


Different types of port scans
1. TCP connect port scan
2. TCP SYN port scan
3. UDP port scan

## TCP and UDP ports

In the same sense that an IP address specifies a host on a network among many others, a TCP port or UDP port is used to identify a network service running on that host.

 A port is usually linked to a service using that specific port number: for instance, an HTTP server would bind to TCP port 80 by default; moreover, if the HTTP server supports SSL/TLS, it would listen on TCP port 443.
 
We can classify ports in two states:
	a) Open port indicates that there is some service listening on that port.
	b) Closed port indicates that there is no service listening on that port.

However, in practical situations, we need to consider the impact of firewalls. Therefore, Nmap considers the following six states:
1. **Open**: indicates that a service is listening on the specified port.
2. **Closed**: indicates that no service is listening on the specified port, although the port is accessible. By accessible, we mean that it is reachable and is not blocked by a firewall or other security appliances/programs.
3. **Filtered**: means that Nmap ***cannot determine*** if the port is open or closed because the port is ***not accessible.*** This state is usually due to a firewall preventing Nmap from reaching that port. Nmap’s packets may be blocked from reaching the port; alternatively, the responses are blocked from reaching Nmap’s host.
4. **Unfiltered**: means that Nmap ***cannot determine*** if the port is open or closed, although the port **is accessible**. This state is encountered when using an ACK scan `-sA`.
5. **Open|Filtered**: This means that Nmap cannot determine whether the port is open or filtered.
6. **Closed|Filtered**: This means that Nmap cannot decide whether a port is closed or filtered.

## TCP Flags

Nmap supports different types of TCP port scans. To understand the difference between these port scans, we need to review the TCP header.

The TCP header is the first 24 bytes of a TCP segment:

![[Pasted image 20240728035824.png]]

Setting a flag bit means setting its value to 1. From left to right, the TCP header flags are:

1. **URG**: Urgent flag indicates that the urgent pointer filed is significant. The urgent pointer indicates that the incoming data is urgent, and that a TCP segment with the URG flag set is processed immediately without consideration of having to wait on previously sent TCP segments.
2. **ACK**: Acknowledgement flag indicates that the acknowledgement number is significant. It is used to acknowledge the receipt of a TCP segment.
3. **PSH**: Push flag asking TCP to pass the data to the application promptly.
4. **RST**: Reset flag is used to reset the connection. Another device, such as a firewall, might send it to tear a TCP connection. This flag is also used when data is sent to a host and there is no service on the receiving end to answer.
5. **SYN**: Synchronize flag is used to initiate a TCP 3-way handshake and synchronize sequence numbers with the other host. The sequence number should be set randomly during TCP connection establishment.
6. **FIN**: The sender has no more data to send.


## TCP Connect Scan

TCP connect scan works by completing the TCP 3-way handshake. In standard TCP connection establishment, the client sends a TCP packet with SYN flag set, and the server responds with SYN/ACK if the port is open; finally, the client completes the 3-way handshake by sending an ACK.

We are interested in learning whether the TCP port is open, not establishing a TCP connection. Hence the connection is torn as soon as its state is confirmed by sending a RST/ACK. 

You can choose to run TCP connect scan using `-sT`.

![[Pasted image 20240728041253.png]]

![[Pasted image 20240728040946.png]]


## TCP SYN Scan

Unprivileged users are limited to connect scan. However, the default scan mode is SYN scan, and it *requires a privileged (root or sudoer) user to run it*.

SYN scan does not need to complete the TCP 3-way handshake; instead, it tears down the connection once it receives a response from the server.

Because we didn’t establish a TCP connection, this decreases the chances of the scan being logged. 

We can select this scan type by using the `-sS` option. 

The figure below shows how the TCP SYN scan works without completing the TCP 3-way handshake.
![[Pasted image 20240728041404.png]]

![[Pasted image 20240728041552.png]]

 1) In the upper half of the following figure, we can see a TCP connect scan `-sT` traffic. Any open TCP port will require Nmap to complete the TCP 3-way handshake before closing the connection. 
 2) In the lower half of the following figure, we see how a SYN scan `-sS` does not need to complete the TCP 3-way handshake; instead, Nmap sends an RST packet once a SYN/ACK packet is received.

![[Pasted image 20240728052838.png]]


## UDP Scan

UDP is a connectionless protocol, and hence it *does not require any handshake* for connection establishment.

 If a UDP packet is sent to a closed port, an ICMP port unreachable error (type 3, code 3) is returned.
	  You can select UDP scan using the `-sU` option; moreover, you can combine it with another TCP scan.

![[Pasted image 20240728052716.png]]

![[Pasted image 20240728052754.png]]


![[Pasted image 20240728052820.png]]

## Fine-Tuning Scope and Performance

You can specify the ports you want to scan instead of the default 1000 ports

*Example:*
- port list: `-p22,80,443` will scan ports 22, 80 and 443.
- port range: `-p1-1023` will scan all ports between 1 and 1023 inclusive, while `-p20-25` will scan ports between 20 and 25 inclusive.

You can request the scan of all ports by using `-p-`, which will scan all 65535 ports. If you want to scan the most common 100 ports, add `-F`. Using `--top-ports 10` will check the ten most common ports.

You can control the scan timing using `-T<0-5>`. `-T0` is the slowest (paranoid), while `-T5` is the fastest. According to Nmap manual page, there are six templates:
- paranoid (0)
- sneaky (1)
- polite (2)
- normal (3)
- aggressive (4)
- insane (5)

*Note:*
	 `-T4` is often used during CTFs and when learning to scan on practice targets, whereas `-T1` is often used during real engagements where stealth is more important.

Control the packet rate using `--min-rate <number>` and `--max-rate <number>`. For example, `--max-rate 10` or `--max-rate=10` ensures that your scanner is not sending more than ten packets per second.

Control probing parallelization using `--min-parallelism <numprobes>` and `--max-parallelism <numprobes>`. Nmap probes the targets to discover which hosts are live and which ports are open; probing parallelization specifies the number of such probes that can be run in parallel.

*Example:*
	 `--min-parallelism=512` pushes Nmap to maintain at least 512 probes in parallel; these 512 probes are related to host discovery and open ports.

## Summary

|Port Scan Type|Example Command|
|---|---|
|TCP Connect Scan|`nmap -sT 10.10.113.228`|
|TCP SYN Scan|`sudo nmap -sS 10.10.113.228`|
|UDP Scan|`sudo nmap -sU 10.10.113.228`|

|Option|Purpose|
|---|---|
|`-p-`|all ports|
|`-p1-1023`|scan ports 1 to 1023|
|`-F`|100 most common ports|
|`-r`|scan ports in consecutive order|
|`-T<0-5>`|-T0 being the slowest and T5 the fastest|
|`--max-rate 50`|rate <= 50 packets/sec|
|`--min-rate 15`|rate >= 15 packets/sec|
|`--min-parallelism 100`|at least 100 probes in parallel|
