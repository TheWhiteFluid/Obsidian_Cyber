
## TCP Null Scan, FIN Scan, and Xmas Scan
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
 
## #Xmas Scan
An Xmas scan sets the `FIN`, `PSH`, and `URG` flags simultaneously. 
 
 Like the Null scan and FIN scan, if an RST packet is received, it means that the port is closed. Otherwise, it will be reported as open|filtered.
 ![[Pasted image 20240730042959.png]]
 
 
 You can select Xmas scan with the option `-sX`:
 ![[Pasted image 20240730043027.png]]


## TCP ACK, Window, and Custom Scan

### #ACK Scan
As the name implies, an ACK scan will send a TCP packet with the ACK flag set.

The target would respond to the ACK with RST regardless of the state of the port. This behaviour happens because a TCP packet with the ACK flag set should be sent only in response to a received TCP packet to acknowledge the receipt of some data, unlike our case. 

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

Although we know that these three ports are not closed, we realize they responded differently, indicating that the firewall does not block them.

![[Pasted image 20240730051206.png]]

### #Custom Scan
If you want to experiment with a new TCP flag combination beyond the built-in TCP scan types, you can do so using `--scanflags`

 For instance, if you want to set `SYN`, `RST`, and `FIN` simultaneously, you can do so using
  `--scanflags RSTSYNFIN`
  
![[Pasted image 20240730051458.png]]

*Note:*
	 It is essential to note that the ACK scan and the window scan were very efficient at helping us map out the firewall rules. However, it is vital to remember that just because a firewall is not blocking a specific port, it does not necessarily mean that a service is listening on that port.  (*there is a possibility that the firewall rules need to be updated to reflect recent service changes. Hence, ACK and window scans are exposing the firewall rules, not the services.*)


## Spoofing and Decoys
