Nmap is an industry-standard tool for mapping networks, identifying live hosts, and discovering running services. A Nmap scan usually goes through the steps shown in the figure below, although many are optional and depend on the command-line arguments you provide.

![[Pasted image 20240726223921.png]]

## **Subnetworks**
 A _network segment_ is a group of computers connected using a shared medium. For instance, the medium can be the Ethernet switch or WiFi access point. In an IP network, a _subnetwork_ is usually the equivalent of one or more network segments connected together and configured to use the same router.
 
*The network segment refers to a physical connection, while a subnetwork refers to a logical connection.

A subnetwork, or simply a subnet, has its own IP address range and is connected to a more extensive network via a router.

![[Pasted image 20240726224139.png]]

- Subnets with `/16`, which means that the subnet mask can be written as `255.255.0.0`. This subnet can have around 65 thousand hosts.
- Subnets with `/24`, which indicates that the subnet mask can be expressed as `255.255.255.0`. This subnet can have around 250 hosts.

 If you are connected to the **same subnet**, you would expect your scanner to rely on ARP (Address Resolution Protocol) queries to discover live hosts. An ARP query aims to get the hardware address (MAC address) so that communication over the link-layer becomes possible;
 
If you are connected to a subnet **different** from the subnet of the target system(s), all packets generated by your scanner will be routed via the default gateway (router) to reach the systems on another subnet;  ARP queries won’t be routed and hence cannot cross the subnet router. ARP is a link-layer protocol, and ARP packets are bound to their subnet.

## **Enumerating Targets**
Generally speaking, you can provide a **list**, a **range**, or a **subnet**. Examples of target specification are:
- **list**: `MACHINE_IP scanme.nmap.org example.com` 
- **range**: `10.11.12.15-20` will scan 6 IP addresses: `10.11.12.15`, `10.11.12.16`,… and `10.11.12.20`.
- **subnet**: `MACHINE_IP/30` will scan 4 IP addresses.

`nmap -iL list_of_hosts.txt` - scan list of host
`nmap -sL TARGET` - perform a list scan with DNS resolution

`nmap -sL -n TARGET` - perform a list scan without  DNS resolution (-n)
![[Pasted image 20240726225145.png]]

`nmap -sL -n RANGE OF IPS` - list scan of the whole range of IPs provided
![[Pasted image 20240726235644.png]]

## **Discovering Live Hosts**
We will leverage the protocols to discover the live hosts. Starting from bottom to top, we can use:
- **ARP** from **Link** Layer
- **ICMP** from **Network** Layer
- **TCP** from **Transport** Layer
- **UDP** from **Transport** Layer

![[Pasted image 20240727005356.png]]

 - **ARP** has one purpose: sending a frame to the broadcast address on the network segment and asking the computer with a specific IP address to respond by providing its MAC (hardware) address.
- **ICMP** has [many types](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml). ICMP ping uses Type 8 (Echo) and Type 0 (Echo Reply). 
  If you want to ping a system on the same subnet, an **ARP** query should precede the **ICMP Echo**.
- **TCP** and **UDP** are transport layers, for network scanning purposes, a scanner can send a specially-crafted packet to common **TCP** or **UDP** ports to check whether the target will respond. This method is efficient, especially when **ICMP Echo** is blocked.

## **Nmap Host Discovery Using ARP**
 There are various ways to discover online hosts. When no host discovery options are provided, Nmap follows the following approaches to discover live hosts:
1. When a **_privileged_ user** tries to scan targets on a **local network** (Ethernet), Nmap uses **_ARP requests_**. A privileged user is `root` or a user who belongs to `sudoers` and can run `sudo`.
2. When a **_privileged_ user** tries to scan targets **outside** the local network, Nmap uses **ICMP echo** requests, **TCP ACK** (Acknowledge) to port **80**, **TCP SYN** (Synchronize) to port **443**, and ICMP timestamp request.
3. When an **_unprivileged_ user** tries to scan targets outside the local network, Nmap resorts to a **TCP 3-way handshake** by sending **SYN** packets to ports **80 and 443**.

 If you want to use Nmap to discover online hosts without port-scanning the live systems, you can issue `nmap -sn TARGETS`
 
ARP scan is possible only if you are on the same subnet as the target systems. On an Ethernet (802.3) and WiFi (802.11), you need to know the MAC address of any system before you can communicate with it. 

The MAC address is necessary for the link-layer header; the header contains the source MAC address and the destination MAC address among other fields. To get the MAC address, the OS sends an ARP query. A host that replies to ARP queries is up. 

If you want Nmap only to perform an ARP scan without port-scanning, you can use `nmap -PR -sn TARGETS`, where `-PR` indicates that you only want an ARP scan.
![[Pasted image 20240727034113.png]]

## **Nmap Host Discovery Using ICMP**
Many firewalls block ICMP echo; new versions of MS Windows are configured with a host firewall that blocks ICMP echo requests by default. Remember that an ARP query will precede the ICMP request if your target is on the same subnet.

**ICMP Echo**
	To use ICMP echo request to discover live hosts, add the option `-PE`. (Remember to add `-sn` if you don’t want to follow that with a port scan.)
![[Pasted image 20240727035443.png]]

**ICMP Timestamp**
	To use ICMP timestamp echo request to discover live hosts, add the option `-PP` 
![[Pasted image 20240727035631.png]]

**ICMP Address Mask**
	To use ICMP address mask echo request to discover live hosts, add the option `-PM` 
![[Pasted image 20240727035827.png]]

**Note:** Based on earlier scans, we know that at least eight hosts are up, this scan returned none. The reason is that the target system or a firewall on the route is blocking this type of ICMP packet. Therefore, it is essential to learn multiple approaches to achieve the same result. If one type of packet is being blocked, we can always choose another to discover the target network and services.

## **Nmap Host Discovery Using TCP and UDP**

### TCP SYN Ping
We can send a packet with the SYN (Synchronize) flag set to a TCP port, 80 by default, and wait for a response. 
- An open port should reply with a SYN/ACK (Acknowledge); 
- A closed port would result in an RST (Reset).

If you want Nmap to use TCP SYN ping, you can do so via the option `-PS` followed by the port number, range, list, or a combination of them.

*Examples:*
- `-PS21` will target port 21.
-  `-PS21-25` will target ports 21, 22, 23, 24, and 25. 
- `-PS80,443,8080` will target the three ports 80, 443, and 8080.

*Note:*
	- **Privileged** users (root and sudoers) can send TCP SYN packets and don’t need to complete the TCP 3-way handshake even if the port is open.
	- **Unprivileged** users have no choice but to complete the 3-way handshake if the port is open.

![[Pasted image 20240727040906.png]]

![[Pasted image 20240727040702.png]]

### TCP ACK Ping
*Note:*
	You must be running Nmap as a privileged user.
	 If you try it as an unprivileged user, Nmap will attempt a 3-way handshake.

The syntax is similar to TCP SYN ping. `-PA` should be followed by a port number, range, list, or a combination of them. For example, consider `-PA21`, `-PA21-25` and `-PA80,443,8080`. If no port is specified, port 80 will be used.

![[Pasted image 20240727040929.png]]

![[Pasted image 20240727040941.png]]

### UDP Ping
Contrary to TCP ping, sending a UDP packet to an open port is not expected to lead to any reply. However, if we send a UDP packet to a closed UDP port, we expect to get an ICMP port unreachable packet; this indicates that the target system is up and available.

The syntax to specify the ports is similar to that of TCP SYN ping and TCP ACK ping; Nmap uses `-PU` for UDP ping.

![[Pasted image 20240727041124.png]]

![[Pasted image 20240727041156.png]]

### Masscan
Masscan uses a similar approach to discover the available systems. However, to finish its network scan quickly, Masscan is quite aggressive with the rate of packets it generates.

The syntax is quite similar: `-p` can be followed by a port number, list, or range.

*Examples:*
- `masscan MACHINE_IP/24 -p443`
- `masscan MACHINE_IP/24 -p80,443`
- `masscan MACHINE_IP/24 -p22-25`

## **Using Reverse-DNS Lookup**
Nmap’s default behaviour is to use reverse-DNS online hosts. Because the hostnames can reveal a lot, this can be a helpful step. However, if you don’t want to send such DNS queries, you use `-n` to skip this step.

To have Nmap perform reverse DNS lookups for all possible hosts on a subnet, you should use the `-R` option. This option forces reverse DNS resolution on all the IP addresses in the target range.

				![[Pasted image 20240727042631.png]]


## **Summary**

| Scan Type              | Example Command                             |
| ---------------------- | ------------------------------------------- |
| Enumerating targets    | `nmap -sL -n MACHINE_IP`                    |
| ARP Scan               | `sudo nmap -PR -sn MACHINE_IP/24`           |
| ICMP Echo Scan         | `sudo nmap -PE -sn MACHINE_IP/24`           |
| ICMP Timestamp Scan    | `sudo nmap -PP -sn MACHINE_IP/24`           |
| ICMP Address Mask Scan | `sudo nmap -PM -sn MACHINE_IP/24`           |
| TCP SYN Ping Scan      | `sudo nmap -PS22,80,443 -sn MACHINE_IP/30`  |
| TCP ACK Ping Scan      | `sudo nmap -PA22,80,443 -sn MACHINE_IP/30`  |
| UDP Ping Scan          | `sudo nmap -PU53,161,162 -sn MACHINE_IP/30` |

| Option | Purpouse                         |
| ------ | -------------------------------- |
| -n     | no DNS lookpup                   |
| -R     | reverse DNS lookup for all hosts |
| -sn    | host discovery only              |

*Note:* 
	Remember to add `-sn` if you are only interested in host discovery without port-scanning. Omitting `-sn` will let Nmap default to port-scanning the live hosts.