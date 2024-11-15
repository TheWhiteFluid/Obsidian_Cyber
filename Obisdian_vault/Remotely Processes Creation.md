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