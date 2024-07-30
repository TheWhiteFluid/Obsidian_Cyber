
### Null Scan
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

  
## FIN Scan

The FIN scan sends a TCP packet with the `FIN` flag set. Similarly, no response will be sent if the TCP port is open. Again, Nmap cannot be sure if the port is open or if a firewall is blocking the traffic related to this TCP port.

![[Pasted image 20240730041448.png]]

However, the target system should respond with an RST if the port is closed. Consequently, we will be able to know which ports are closed and use this knowledge to infer the ports that are open or filtered.

![[Pasted image 20240730041545.png]]

*Note:*
	 It's worth noting some firewalls will 'silently' drop the traffic without sending an RST.


You can choose this scan type using the `-sF` option:
![[Pasted image 20240730041611.png]]
 
## Xmas Scan
