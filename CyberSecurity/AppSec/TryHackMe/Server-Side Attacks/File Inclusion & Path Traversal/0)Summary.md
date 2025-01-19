File Inclusion and Path Traversal are vulnerabilities that arise when an application allows external input to change the path for accessing files. For example, imagine a library where the catalogue system is manipulated to access restricted books not meant for public viewing. Similarly, in web applications, the vulnerabilities primarily arise from improper handling of file paths and URLs. These vulnerabilities allow attackers to include files not intended to be part of the web application, leading to unauthorized access or execution of code.

## Structure of a Web Application
Web applications are complex systems comprising several components working together to deliver a seamless user experience. At its core, a web application has two main parts: the frontend and the backend.

1. **Frontend:** This is the user interface of the application, typically built using frameworks like React, Angular, or Vue.js. It communicates with the backend via APIs.
2. **Backend:** This server-side component processes user requests, interacts with databases, and serves data to the frontend. It's often developed using languages like PHP, Python, and Javascript and frameworks like Node.js, Django, or Laravel.

One of the fundamental aspects of web applications is the client-server model. In this model, the client, usually a web browser, sends a request to the server hosting the web application. The backend server then processes this request and sends back a response. The client and server communication usually happens over the HTTP/HTTPS protocols.
	![](Pasted%20image%2020250119141544.png)
**Server-Side Scripting and File Handling**  
Server-side scripts run on the server and generate the content of the frontend, which is then sent to the client. Unlike client-side scripts like JavaScript in the browser, server-side scripts can access the server's file system and databases. File handling is a significant part of server-side scripting. Web applications often need to read from or write to files on the server. For example, reading configuration files, saving user uploads, or including code from other files.

For example, the application below includes a file based on user input.
	![](Pasted%20image%2020250119141724.png)
If this input is not correctly validated and sanitized, an attacker might exploit the vulnerable parameter to include malicious files or access sensitive files on the server. In this case, the attacker could view the contents of the server's **passwd** file.
	![](Pasted%20image%2020250119141741.png)
In short, file inclusion and path traversal vulnerabilities arise when user inputs are not properly sanitized or validated. Since attackers can inject malicious payloads to log files `/var/log/apache2/access.log` and manipulate file paths to execute the logged payload, an attacker can achieve remote code execution. An attacker may also read configuration files that contain sensitive information, like database credentials, if the application returns the file in plaintext. Lastly, insufficient error handling may also reveal system paths or file structures, providing clues to attackers about potential targets for path traversal or file inclusion attacks.

## Types of File Inclusion

### **Basics of File Inclusion**
A traversal string, commonly seen as `../`, is used in path traversal attacks to navigate through the directory structure of a file system. It's essentially a way to move up one directory level. Traversal strings are used to access files outside the intended directory.

Relative pathing refers to locating files based on the current directory. For example, `include('./folder/file.php')` implies that `file.php` is located inside a folder named `folder`, which is in the same directory as the executing script.

Absolute pathing involves specifying the complete path starting from the root directory. For example, `/var/www/html/folder/file.php` is an absolute path.


### **Remote File Inclusion**
Remote File Inclusion, or RFI, is a vulnerability that allows attackers to include remote files, often through input manipulation. This can lead to the execution of malicious scripts or code on the server.