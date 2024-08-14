Metasploit has a database function to simplify project management and avoid possible confusion when setting up parameter values. 

You will first need to start the PostgreSQL database, which Metasploit will use with the following command:  `systemctl start postgresql`

Initialise the Metasploit Database using `msfdb init`
![[Pasted image 20240815023325.png]]

The database feature will allow you to create workspaces to isolate different projects. When first launched, you should be in the default workspace. You can list available workspaces using the `workspace` command.
![[Pasted image 20240815023404.png]]

Add a workspace using the `-a` parameter or delete a workspace using the `-d` parameter. You can use the workspace command to navigate between workspaces simply by typing `workspace` followed by the desired workspace name.
![[Pasted image 20240815023437.png]]

You can use the `workspace -h` command to list available options for the `workspace` command.
![[Pasted image 20240815023542.png]]

Different from regular Metasploit usage, once Metasploit is launched with a database, the `help` command, you will show the Database Backends Commands menu.
![[Pasted image 20240815023606.png]]

  
If you run a Nmap scan using the `db_nmap` shown below, all results will be saved to the database.
![[Pasted image 20240815023623.png]]

You can now reach information relevant to hosts and services running on target systems with the `hosts` and `services` commands, respectively. The `hosts -h` and `services -h` commands can help you become more familiar with available options. 
![[Pasted image 20240815023642.png]]

Once the host information is stored in the database, you can use the `hosts -R` command to add this value to the RHOSTS parameter.

**Example Workflow**
1. We will use the vulnerability scanning module that finds potential MS17-010 vulnerabilities with the `use auxiliary/scanner/smb/smb_ms17_010` command.
2. We set the RHOSTS value using `hosts -R`.
3. We have typed `show options` to check if all values were assigned correctly. (In this example, 10.10.138.32 is the IP address we have scanned earlier using the `db_nmap` command)
4. Once all parameters are set, we launch the exploit using the `run` or `exploit` command.

*Note:*
	If there is more than one host saved to the database, all IP addresses will be used when the `hosts -R` command is used.   

The services command used with the `-S` parameter will allow you to search for specific services in the environment.
![[Pasted image 20240815023844.png]]

You may want to look for low-hanging fruits such as:
- **HTTP**: Could potentially host a web application where you can find vulnerabilities like SQL injection or Remote Code Execution (RCE). 
- **FTP**: Could allow anonymous login and provide access to interesting files. 
- **SMB**: Could be vulnerable to SMB exploits like MS17-010
- **SSH**: Could have default or easy to guess credentials
- **RDP**: Could be vulnerable to Bluekeep or allow desktop access if weak credentials were used.

In a typical penetration testing engagement, we could have the following scenario: 
- Finding available hosts using the `db_nmap` command
- Scanning these for further vulnerabilities or open ports (using a port scanning module)