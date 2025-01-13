![](Pasted%20image%2020250113222430.png)

Two ports are open, port 22 and port 80. Whenever I see SSH on an assessment, I know I will want to brute force against it , test weak/default credentials, or possibly do a banner grab.

# RECONNAISSANCE TO-DO LIST
Next, I like to create a to-do list to stay organized during my testing. I may not need to complete the entire list, but it serves as a solid starting point for web application testing.

1. Check web application functionality
2. Check source code
3. Directory enumeration
4. Vhost fuzzing
5. /robots.txt

# WEB APPLICATION FUNCTIONALITY
Clicking around the website, I only have access to a login page and an Admin login page.
![](Pasted%20image%2020250113223813.png)

Let's inspect the main page source code:
![](Pasted%20image%2020250113223938.png)

After inspecting the source code, I found the existence of a _mail.log_ file.

# DIRECTORY ENUMERATION
