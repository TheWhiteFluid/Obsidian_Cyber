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
	