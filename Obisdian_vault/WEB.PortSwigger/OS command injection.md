[OS Command Injection](https://www.hackingarticles.in/comprehensive-guide-on-os-command-injection/) (git)

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
    `email=x||ping+-c+10+127.0.0.1||`

Analysis:

