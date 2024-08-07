
## **TCP Null Scan, FIN Scan, and Xmas Scan**
### #Null Scan
The null scan does not set any flag; all six flag bits are set to zero. A TCP packet with no flags set will not trigger any response when it reaches an open port. 

A lack of reply in a null scan indicates that either the port is open or a firewall is blocking the packet.
![[Pasted image 20240730041104.png]]

If the port is closed we expect that server to respond with an RST packet.
![[Pasted image 20240730041202.png]]

 Because the null scan relies on the lack of a response to infer that the port is not closed, it cannot indicate with certainty that these ports are open; there is a possibility that the ports are not responding due to a firewall rule.

You can choose this scan using the `-sN` option:
![[Pasted image 20240730041301.png]]

*Note:* 
	Many Nmap options require root privileges. Unless you are running Nmap as root, you need to use `sudo` as in the example above using the `-sN` option.
  
### #FIN Scan
The FIN scan sends a TCP packet with the `FIN` flag set.

Similarly, no response will be sent if the TCP port is open. Again, Nmap cannot be sure if the port is open or if a firewall is blocking the traffic related to this TCP port.
![[Pasted image 20240730041448.png]]

However, the target system should respond with an RST if the port is closed. Consequently, we will be able to know which ports are closed and use this knowledge to infer the ports that are open or filtered.
![[Pasted image 20240730041545.png]]

*Note:*
	 It's worth noting some firewalls will 'silently' drop the traffic without sending an RST.

You can choose this scan type using the `-sF` option:
![[Pasted image 20240730041611.png]]
 
### #Xmas Scan
An Xmas scan sets the `FIN`, `PSH`, and `URG` flags simultaneously. 
 
 Like the Null scan and FIN scan, if an RST packet is received, it means that the port is closed. Otherwise, it will be reported as open|filtered.![[Pasted image 20240730042959.png]]
 
 You can select Xmas scan with the option `-sX`:![[Pasted image 20240730043027.png]]

## **TCP ACK, Window, and Custom Scan**

### #ACK Scan
As the name implies, an ACK scan will send a TCP packet with the ACK flag set.

The target would respond with RST regardless of the state of the port. This behaviour happens because a TCP packet with the ACK flag set should be sent only in response to a received TCP packet to acknowledge the receipt of some data, unlike our case. 

This scan won’t tell us whether the target port is open in a simple setup.
![[Pasted image 20240730045416.png]]


Use the `-sA` option to choose this scan:
![[Pasted image 20240730045430.png]]

This kind of scan would be helpful if there is a firewall in front of the target. Consequently, based on which ACK packets resulted in responses, you will learn which ports were not blocked by the firewall. 

*Note:*
	This type of scan is more suitable to discover firewall rule sets and configuration.

After setting up the target VM  with a firewall, we repeated the ACK scan. As seen in the console output below, we have three ports that aren't being blocked by the firewall. This result indicates that the firewall is blocking all other ports except for these three ports.
![[Pasted image 20240730050819.png]]

### #Window Scan
Another similar scan is the TCP window scan. The TCP window scan is almost the same as the ACK scan; however, it examines the TCP Window field of the RST packets returned.

![[Pasted image 20240730050953.png]]

Similarly, launching a TCP window scan against a Linux system with no firewall will not provide much information. As we can see in the console output below, the results of the window scan against a Linux server with no firewall didn’t give any extra information compared to the ACK scan executed earlier.

You can select this scan type with the option `-sW`:
![[Pasted image 20240730051024.png]]

If we repeat our TCP window scan against a server behind a firewall, we expect to get more satisfying results. In the console output shown below, the TCP window scan pointed that three ports are detected as closed. (This is in contrast with the ACK scan that labelled the same three ports as unfiltered.) 

Although we know that these three ports are not closed, we realise they responded differently, indicating that the firewall does not block them.
![[Pasted image 20240730051206.png]]

### #Custom Scan
If you want to experiment with a new TCP flag combination beyond the built-in TCP scan types, you can do so using `--scanflags`

 For instance, if you want to set `SYN`, `RST`, and `FIN` simultaneously, you can do so using
  `--scanflags RSTSYNFIN`
  
![[Pasted image 20240730051458.png]]

*Note:*
	 It is essential to note that the ACK scan and the window scan were very efficient at helping us map out the firewall rules. However, it is vital to remember that just because a firewall is not blocking a specific port, it does not necessarily mean that a service is listening on that port.  (*there is a possibility that the firewall rules need to be updated to reflect recent service changes. Hence, ACK and window scans are exposing the firewall rules, not the services.*)

## **Spoofing and Decoys**
In some network setups, you will be able to scan a target system using a spoofed IP address and even a spoofed MAC address. 

*Note:*
	Such a scan is only beneficial in a situation where you can guarantee to capture the response. If you try to scan a target from some random network using a spoofed IP address, chances are you won’t have any response routed to you, and the scan results could be unreliable.

The following figure shows the attacker launching the command `nmap -S SPOOFED_IP MACHINE_IP`. Consequently, Nmap will craft all the packets using the provided source IP address `SPOOFED_IP`. The target machine will respond to the incoming packets sending the replies to the destination IP address `SPOOFED_IP`.

![[Pasted image 20240730180500.png]]

In brief, scanning with a spoofed IP address is three steps:
1. Attacker sends a packet with a spoofed source IP address to the target machine.
2. Target machine replies to the spoofed IP address as the destination.
3. Attacker captures the replies to figure out open ports.

*Note:*
	In general, you expect to specify the network interface using `-e` and to explicitly disable ping scan `-Pn`. 

 You will need to issue `nmap -e NET_INTERFACE -Pn -S SPOOFED_IP MACHINE_IP` to tell Nmap explicitly which network interface to use and not to expect to receive a ping reply.

When you are on the same subnet as the target machine, you would be able to spoof your MAC address as well. You can specify the source MAC address using `--spoof-mac SPOOFED_MAC`. 

*Note:*
	This address spoofing is only possible if the attacker and the target machine are on the same Ethernet (802.3) network or same WiFi (802.11).

You can launch a decoy scan by specifying a specific or random IP address after `-D`. 

For example, `nmap -D 10.10.0.1,10.10.0.2,ME MACHINE_IP` will make the scan of MACHINE_IP appear as coming from the IP addresses 10.10.0.1, 10.10.0.2, and then `ME`.

![[Pasted image 20240730180934.png]]

Another example command would be `nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME MACHINE_IP`, where the third and fourth source IP addresses are assigned randomly, while the fifth source is going to be the attacker’s IP address.

## **Fragmented Packets**

### #Firewall
A firewall is a piece of software or hardware that permits packets to pass through or blocks them. It functions based on firewall rules, summarized as blocking all traffic with exceptions or allowing all traffic with exceptions. A traditional firewall inspects, at least, the IP header and the transport layer header. A more sophisticated firewall would also try to examine the data carried by the transport layer.

### #IDS
An intrusion detection system (IDS) inspects network packets for select behavioural patterns or specific content signatures. It raises an alert whenever a malicious rule is met. In addition to the IP header and transport layer header, an IDS would inspect the data contents in the transport layer and check if it matches any malicious patterns. Depending on the type of firewall/IDS, you might benefit from dividing the packet into smaller packets.

### Fragmented Packets
Nmap provides the option `-f` to fragment packets. Once chosen, the IP data will be divided into 8 bytes or less. Adding another `-f` (`-f -f` or `-ff`) will split the data into 16 byte-fragments instead of 8. You can change the default value by using the `--mtu`; however, you should always choose a multiple of 8.

To properly understand fragmentation, we need to look at the IP header in the figure below. In particular, notice the source address taking 32 bits (4 bytes) on the fourth row, while the destination address is taking another 4 bytes on the fifth row.
![[Pasted image 20240730182003.png]]

The data that we will fragment across multiple packets is highlighted in red. To aid in the reassembly on the recipient side, IP uses the identification (ID) and fragment offset.

Let’s compare running `sudo nmap -sS -p80 10.20.30.144` and `sudo nmap -sS -p80 -f 10.20.30.144`. This will use stealth TCP SYN scan on port 80; however, in the second command, we are requesting Nmap to fragment the IP packets.

In the first two lines, we can see an ARP query and response. Nmap issued an ARP query because the target is on the same Ethernet.
	The second two lines show a TCP SYN ping and a reply.
		The fifth line is the beginning of the port scan; Nmap sends a TCP SYN packet to p.80

![[Pasted image 20240730190706.png]]

*In this case, the IP header is 20 bytes, and the TCP header is 24 bytes. Note that the minimum size of the TCP header is 20 bytes.

With fragmentation requested via `-f`, the 24 bytes of the TCP header will be divided into multiples of 8 bytes, with the last fragment containing 8 bytes or less of the TCP header. Since 24 is divisible by 8, we got 3 IP fragments; each has 20 bytes of IP header and 8 bytes of TCP header.
![[Pasted image 20240730190757.png]]

*Note:* 
	If you added `-ff` (or `-f -f`), the fragmentation of the data will be multiples of 16. In other words, the 24 bytes of the TCP header, in this case, would be divided over two IP fragments, the first containing 16 bytes and the second containing 8 bytes of the TCP header.

If you prefer to increase the size of your packets to make them look innocuous, you can use the option `--data-length NUM`, where num specifies the number of bytes you want to append to your packets.

## **Idle/Zombie Scan**
The idle scan, or zombie scan, requires an idle system connected to the network that you can communicate with. Practically, Nmap will make each probe appear as if coming from the idle (zombie) host, then it will check for indicators whether the idle (zombie) host received any response to the spoofed probe.

This is accomplished by checking the IP identification (IP ID) value in the IP header. You can run an idle scan using `nmap -sI ZOMBIE_IP MACHINE_IP`, where `ZOMBIE_IP` is the IP address of the idle host (zombie).

The idle (zombie) scan requires the following three steps to discover whether a port is open:
1. Trigger the idle host to respond so that you can record the current IP ID on the idle host.
2. Send a SYN packet to a TCP port on the target. The packet should be spoofed to appear as if it was coming from the idle host (zombie) IP address.
3. Trigger the idle machine again to respond so that you can compare the new IP ID with the one received earlier.
	![[Pasted image 20240731005031.png]]

The attacker will send a SYN packet to the TCP port they want to check on the target machine in the next step. However, this packet will use the idle host (zombie) IP address as the source. 

Three scenarios would arise:
1) In the first scenario, shown in the figure below, the TCP port is closed; therefore, the target machine responds to the idle host with an RST packet. The idle host does not respond; hence its IP ID is not incremented.

![[Pasted image 20240731005145.png]]

2) In the second scenario, as shown below, the TCP port is open, so the target machine responds with a SYN/ACK to the idle host (zombie). The idle host responds to this unexpected packet with an RST packet, thus incrementing its IP ID.

![[Pasted image 20240731005210.png]]

3) In the third scenario, the target machine does not respond at all due to firewall rules. This lack of response will lead to the same result as with the closed port; the idle host won’t increase the IP ID.

For the final step, the attacker sends another SYN/ACK to the idle host. The idle host responds with an RST packet, incrementing the IP ID by one again. The attacker needs to compare the IP ID of the RST packet received in the first step with the IP ID of the RST packet received in this third step. 
	If the difference is 1, it means the port on the target machine was closed or filtered.
	If the difference is 2, it means that the port on the target was open.

*Note:*
	It is worth repeating that this scan is called an idle scan because choosing an idle host is indispensable for the accuracy of the scan. If the “idle host” is busy, all the returned IP IDs would be useless.

## **Getting More Details**
You might consider adding `--reason` if you want Nmap to provide more details regarding its reasoning and conclusions.

```shell-session
pentester@TryHackMe$ sudo nmap -sS 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:39 BST
Nmap scan report for ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27)
Host is up (0.0020s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
111/tcp open  rpcbind
143/tcp open  imap
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.60 seconds
```

```shell-session
pentester@TryHackMe$ sudo nmap -sS --reason 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:40 BST
Nmap scan report for ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27)
Host is up, received arp-response (0.0020s latency).
Not shown: 994 closed ports
Reason: 994 resets
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 64
25/tcp  open  smtp    syn-ack ttl 64
80/tcp  open  http    syn-ack ttl 64
110/tcp open  pop3    syn-ack ttl 64
111/tcp open  rpcbind syn-ack ttl 64
143/tcp open  imap    syn-ack ttl 64
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds
```

Providing the `--reason` flag gives us the explicit reason why Nmap concluded that the system is up or a particular port is open. In this console output above, we can see that this system is considered online because Nmap “received arp-response.” On the other hand, we know that the SSH port is deemed to be open because Nmap received a “syn-ack” packet back.

For more detailed output, you can consider using `-v` for verbose output or `-vv` for even more verbosity.
```shell-session
pentester@TryHackMe$ sudo nmap -sS -vv 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:41 BST
Initiating ARP Ping Scan at 10:41
Scanning 10.10.252.27 [1 port]
Completed ARP Ping Scan at 10:41, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:41
Completed Parallel DNS resolution of 1 host. at 10:41, 0.00s elapsed
Initiating SYN Stealth Scan at 10:41
Scanning ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27) [1000 ports]
Discovered open port 22/tcp on 10.10.252.27
Discovered open port 25/tcp on 10.10.252.27
Discovered open port 80/tcp on 10.10.252.27
Discovered open port 110/tcp on 10.10.252.27
Discovered open port 111/tcp on 10.10.252.27
Discovered open port 143/tcp on 10.10.252.27
Completed SYN Stealth Scan at 10:41, 1.25s elapsed (1000 total ports)
Nmap scan report for ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27)
Host is up, received arp-response (0.0019s latency).
Scanned at 2021-08-30 10:41:02 BST for 1s
Not shown: 994 closed ports
Reason: 994 resets
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 64
25/tcp  open  smtp    syn-ack ttl 64
80/tcp  open  http    syn-ack ttl 64
110/tcp open  pop3    syn-ack ttl 64
111/tcp open  rpcbind syn-ack ttl 64
143/tcp open  imap    syn-ack ttl 64
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds
           Raw packets sent: 1002 (44.072KB) | Rcvd: 1002 (40.092KB)
```

*Note:*
	You can use `-d` for debugging details or `-dd` for even more details.


## **Summary**

| Port Scan Type                 | Example Command                                              |
| ------------------------------ | ------------------------------------------------------------ |
| TCP Null Scan                  | `sudo nmap -sN MACHINE_IP`                                   |
| TCP FIN Scan                   | `sudo nmap -sF MACHINE_IP`                                   |
| TCP Xmas Scan                  | `sudo nmap -sX MACHINE_IP`                                   |
| TCP Maimon Scan                | `sudo nmap -sM MACHINE_IP`                                   |
| TCP ACK Scan                   | `sudo nmap -sA MACHINE_IP`                                   |
| TCP Window Scan                | `sudo nmap -sW MACHINE_IP`                                   |
| Custom TCP Scan                | `sudo nmap --scanflags URGACKPSHRSTSYNFIN MACHINE_IP`        |
| ------------------------------ | ------------------------------------------------------------ |
| Spoofed Source IP              | `sudo nmap -S SPOOFED_IP MACHINE_IP`                         |
| Spoofed MAC Address            | `--spoof-mac SPOOFED_MAC`                                    |
| Decoy Scan                     | `nmap -D DECOY_IP,ME MACHINE_IP`                             |
| ------------------------------ | ------------------------------------------------------------ |
| Idle (Zombie) Scan             | `sudo nmap -sI ZOMBIE_IP MACHINE_IP`                         |
| ------------------------------ | ------------------------------------------------------------ |
| Fragment IP data into 8 bytes  | `-f`                                                         |
| Fragment IP data into 16 bytes | `-ff`                                                        |

These scan types rely on setting TCP flags in unexpected ways to prompt ports for a reply:
- `Null`, `FIN`, and `Xmas` scan provoke a response from closed ports;
- `Maimon`, `ACK`, and `Window` scans provoke a response from open and closed ports.

|Option|Purpose|
|---|---|
|`--source-port PORT_NUM`|specify source port number|
|`--data-length NUM`|append random data to reach given length|

| Option     | Purpose                               |
| ---------- | ------------------------------------- |
| `--reason` | explains how Nmap made its conclusion |
| `-v`       | verbose                               |
| `-vv`      | very verbose                          |
| `-d`       | debugging                             |
| `-dd`      | more details for debugging            |