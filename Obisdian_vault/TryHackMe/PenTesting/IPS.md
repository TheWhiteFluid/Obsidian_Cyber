An Intrusion Detection System (IDS) is a system that detects network or system intrusions. One analogy that comes to mind is a guard watching live feeds from different security cameras. He can spot a theft, but he cannot stop it by himself. However, if this guard can contact another guard and ask them to stop the robber, detection turns into prevention. An Intrusion Detection and Prevention System (IDPS) or simply Intrusion Prevention System (IPS) is a system that can detect and prevent intrusions.

Understanding the difference between _detection_ and _prevention_ is essential. Snort is a network intrusion detection and intrusion prevention system. Consequently, Snort can be set up as an IDS or an IPS. For Snort to function as an IPS, it needs some mechanism to block (`drop`) offending connections. This capability requires Snort to be set up as `inline` and to bridge two or more network cards.

IDS setups can be divided based on their location in the network into:

1. Host-based IDS (HIDS)
2. Network-based IDS (NIDS)

The host-based IDS (HIDS) is installed on an OS along with the other running applications. This setup will give the HIDS the ability to monitor the traffic going in and out of the host; moreover, it can monitor the processes running on the host.

The network-based IDS (NIDS) is a dedicated appliance or server to monitor the network traffic. The NIDS should be connected so that it can monitor all the network traffic of the network or VLANs we want to protect. This can be achieved by connecting the NIDS to a monitor port on the switch. The NIDS will process the network traffic to detect malicious traffic.

In the figure below, we use two red circles to show the difference in the coverage of a HIDS versus a NIDS.

![[Pasted image 20240902023307.png]]

## **IDS Engine Types**
We can classify network traffic into:
1. **Benign traffic**: This is the usual traffic that we expect to have and don’t want the IDS to alert us about.
2. **Malicious traffic**: This is abnormal traffic that we don’t expect to see under normal conditions and consequently want the IDS to detect it.

Consequently, the detection engine of an IDS can be:
1. **Signature-based**: A signature-based IDS requires full knowledge of malicious (or unwanted) traffic. In other words, we need to explicitly feed the signature-based detection engine the characteristics of malicious traffic. Teaching the IDS about malicious traffic can be achieved using explicit rules to match against.
2. **Anomaly-based**: This requires the IDS to have knowledge of what regular traffic looks like. In other words, we need to “teach” the IDS what normal is so that it can recognize what is **not** normal. Teaching the IDS about normal traffic, i.e., baseline traffic can be achieved using machine learning or manual rules.

## **IDS/IPS Rule Triggering**
Each IDS/IPS has a certain syntax to write its rules. For example, Snort uses the following format for its rules: `Rule Header (Rule Options)`, where **Rule Header** constitutes:

1. Action: Examples of action include `alert`, `log`, `pass`, `drop`, and `reject`.
2. Protocol: `TCP`, `UDP`, `ICMP`, or `IP`.
3. Source IP/Source Port: `!10.10.0.0/16 any` refers to everything not in the class B subnet `10.10.0.0/16`.
4. Direction of Flow: `->` indicates left (source) to right (destination), while `<>` indicates bi-directional traffic.
5. Destination IP/Destination Port: `10.10.0.0/16 any` to refer to class B subnet `10.10.0.0/16`.

below is an example rule to `drop` all ICMP traffic passing through Snort IPS:

`drop icmp any any -> any any (msg: "ICMP Ping Scan"; dsize:0; sid:1000020; rev: 1;)`

The rule above instructs the Snort IPS to drop any packet of type ICMP from any source IP address (on any port) to any destination IP address (on any port). The message to be added to the logs is “ICMP Ping Scan.”

Let’s consider a hypothetical case where a vulnerability is discovered in our web server. This vulnerability lies in how our web server handles HTTP POST method requests, allowing the attacker to run system commands.

Let’s consider the following “naive” approach. We want to create a Snort rule that detects the term `ncat` in the payload of the traffic exchanged with our webserver to learn how people exploit this vulnerability.

`alert tcp any any <> any 80 (msg: "Netcat Exploitation"; content:"ncat"; sid: 1000030; rev:1;)`

The rule above inspects the content of the packets exchanged with port 80 for the string `ncat`. Alternatively, you can choose to write the content that Snort will scan for in hexadecimal format. `ncat` in ASCII is written as `6e 63 61 74` in hexadecimal and it is encapsulated as a string by 2 pipe characters `|`.

`alert tcp any any <> any 80 (msg: "Netcat Exploitation"; content:"|6e 63 61 74|"; sid: 1000031; rev:1;)`

We can further refine it if we expect to see it in HTTP POST requests. Note that `flow:established` tells the Snort engine to look at streams started by a TCP 3-way handshake (established connections).

`alert tcp any any <> any 80 (msg: "Netcat Exploitation"; flow:established,to_server; content:"POST"; nocase; http_method; content:"ncat"; nocase; sid:1000032; rev:1;)`

*Note:*
	There are a few points to make about signature-based IDS and its rules. If the attacker made even the slightest changes to avoid using `ncat` verbatim in their payload, the attack would go unnoticed. As we can conclude, a signature-based IDS or IPS is limited to how well-written and updated its signatures (rules) are.

## **Evasion via Protocol Manipulation**
Evading a signature-based IDS/IPS requires that you manipulate your traffic so that it does not match any IDS/IPS signatures. Here are four general approaches you might consider to evade IDS/IPS systems.
1. Evasion via Protocol Manipulation
2. Evasion via Payload Manipulation
3. Evasion via Route Manipulation
4. Evasion via Tactical Denial of Service (DoS)


![[Pasted image 20240902031207.png]]

1. Evasion via **protocol manipulation** includes:
	- Relying on a different protocol;
	- Manipulating (Source) TCP/UDP port;
	- Using session splicing (IP packet fragmentation);
	- Sending invalid packets;
	![[Pasted image 20240902031602.png]]

### Rely on a Different Protocol
The IDS/IPS system might be configured to block certain protocols and allow others. For instance, you might consider using UDP instead of TCP or rely on HTTP instead of DNS to deliver an attack or exfiltrate data. You can use the knowledge you have gathered about the target and the applications necessary for the target organization to design your attack. For instance, if web browsing is allowed, it usually means that protected hosts can connect to ports 80 and 443 unless a local proxy is used. In one case, the client relied on Google services for their business, so the attacker used Google web hosting to conceal his malicious site. Unfortunately, it is not a one-size-fits-all; moreover, some trial and error might be necessary as long as you don’t create too much noise.

We have an IPS set to block DNS queries and HTTP requests in the figure below. In particular, it enforces the policy where local machines cannot query external DNS servers but should instead query the local DNS server; moreover, it enforces secure HTTP communications. It is relatively permissive when it comes to HTTPS. In this case, using HTTPS to tunnel traffic looks like a promising approach to evade the IPS.
	![[Pasted image 20240902032245.png]]

Ncat, by default, uses a TCP connection; however, you can get it to use UDP using the option `-u`.
- To listen using TCP, just issue `ncat -lvnp PORT_NUM` where port number is the port you want to listen to.
- to connect to an Ncat instance listening on a TCP port, you can issue `ncat TARGET_IP PORT_NUM`

Note that:
- `-l` tells `ncat` to listen for incoming connections
- `-v` gets more verbose output as `ncat` binds to a source port and receives a connection
- `-n` avoids resolving hostnames
- `-p` specifies the port number that `ncat` will listen on

As already mentioned, using `-u` will move all communications over UDP.
- To listen using UDP, just issue `ncat -ulvnp PORT_NUM` where port number is the port you want to listen to. Note that unless you add `-u`, `ncat` will use TCP by default.
- To connect to an Ncat instance listening on a UDP port, you can issue `nc -u TARGET_IP PORT_NUM`

Consider the following two examples:
- Running `ncat -lvnp 25` on the attacker system and connecting to it will give the impression that it is a usual TCP connection with an SMTP server, unless the IDS/IPS provides deep packet inspection (DPI).
- Executing `ncat -ulvnp 162` on the attacker machine and connecting to it will give the illusion that it is a regular UDP communication with an SNMP server unless the IDS/IPS supports DPI.
- 
### Manipulate (Source) TCP/UDP Port
Generally speaking, the TCP and UDP source and destination ports are inspected even by the most basic security solutions. Without deep packet inspection, the port numbers are the primary indicator of the service used. In other words, network traffic involving TCP port 22 would be interpreted as SSH traffic unless the security solution can analyze the data carried by the TCP segments.