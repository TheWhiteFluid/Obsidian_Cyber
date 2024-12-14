Before diving in, it's crucial to clearly understand the target machine's database version and operating system details. To achieve this, we can utilise **Nmap**, a powerful network scanning tool, to thoroughly scan the `MACHINE_IP`. This scan will provide valuable insights into the open ports, running services, and the target machine's operating system. For those unfamiliar with Nmap, we recommend reviewing our comprehensive Nmap room to get up to speed on effectively using this tool. Here is the Nmap output after scanning the machine:  
```shell-session
thm@machine$ nmap -A -T4 -p 3306,3389,445,139,135 MACHINE_IP

Starting Nmap 7.60 ( https://nmap.org ) at 2024-05-25 12:03 BST
Nmap scan report for MACHINE_IP
Host is up (0.00034s latency).

PORT     STATE    SERVICE       VERSION
135/tcp  open     msrpc
139/tcp  open     netbios-ssn
445/tcp  open     microsoft-ds
3306/tcp open     mysql
3389/tcp open     ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=SQLi
| Not valid before: 2024-05-23T04:08:44
|_Not valid after:  2024-11-22T04:08:44
|_ssl-date: 2024-05-25T11:03:33+00:00; 0s from scanner time.
MAC Address: 02:87:BD:21:12:33 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized
Running (JUST GUESSING): AVtech embedded (87%)
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.67 seconds
```

The machine is using MySQL service on Windows.

# Types of SQL Injection
![](Pasted%20image%2020241207194046.png)


## IN.band
This technique is considered the most common and straightforward type of SQL injection attack. In this technique, the attacker uses the same communication channel for both the injection and the retrieval of data. There are two primary types of in-band SQL injection:  

- **Error-Based SQL Injection**: The attacker manipulates the SQL query to produce error messages from the database. These error messages often contain information about the database structure, which can be used to exploit the database further. Example: `SELECT * FROM users WHERE id = 1 AND 1=CONVERT(int, (SELECT @@version))`. If the database version is returned in the error message, it reveals information about the database.
- **Union-Based SQL Injection**: The attacker uses the UNION SQL operator to combine the results of two or more SELECT statements into a single result, thereby retrieving data from other tables. Example: `SELECT name, email FROM users WHERE id = 1 UNION ALL SELECT username, password FROM admin`.

## Blind 
Inferential SQL injection does not transfer data directly through the web application, making exploiting it more challenging. Instead, the attacker sends payloads and observes the application’s behaviour and response times to infer information about the database. There are two primary types of inferential SQL injection:  

- **Boolean-Based Blind SQL Injection**: The attacker sends an SQL query to the database, forcing the application to return a different result based on a true or false condition. By analysing the application’s response, the attacker can infer whether the payload was true or false. Example: `SELECT * FROM users WHERE id = 1 AND 1=1 (true condition) versus SELECT * FROM users WHERE id = 1 AND 1=2 (false condition)`. The attacker can infer the result if the page content or behaviour changes based on the condition.
- **Time-Based Blind SQL Injection**: The attacker sends an SQL query to the database, which delays the response for a specified time if the condition is true. By measuring the response time, the attacker can infer whether the condition is true or false. For example, `SELECT * FROM users WHERE id = 1; IF (1=1) WAITFOR DELAY '00:00:05'--`. If the response is delayed by 5 seconds, the attacker can infer that the condition was true.

## OUT.band 
Out-of-band SQL injection is used when the attacker cannot use the same channel to launch the attack and gather results or when the server responses are unstable. This technique relies on the database server making an out-of-band request (e.g., HTTP or DNS) to send the query result to the attacker. HTTP is normally used in out-of-band SQL injection to send the query result to the attacker's server. We will discuss it in detail in this room.


Note:
	 *In-band SQL* Injection is easy to exploit and detect but noisy and can be easily monitored. 
	 *Inferential (Blind)* SQL Injection is more challenging to exploit and requires multiple requests but can be used when detailed error messages are unavailable. 
	 *Out-of-band* SQL Injection is less common and highly effective, requires external server control, and relies on the database’s ability to make out-of-band requests.
	 
By mastering these techniques, penetration testers can effectively identify and exploit SQL injection vulnerabilities, helping organisations secure their web applications against these critical threats.