Second-order SQL injection, also known as stored SQL injection, exploits vulnerabilities where user-supplied input is saved and subsequently used in a different part of the application, possibly after some initial processing. This type of attack is more insidious because the malicious SQL code does not need to immediately result in a SQL syntax error or other obvious issues, making it harder to detect with standard input validation techniques. The injection occurs upon the second use of the data when it is retrieved and used in a SQL command, hence the name "**Second Order**".
	![](Pasted%20image%2020241207194811.png)

*Impact:*
The danger of Second-Order SQL Injection lies in its ability to bypass typical front-end defences like basic input validation or sanitization, which only occur at the point of initial data entry. Since the payload does not cause disruption during the first step, it can be overlooked until it's too late, making the attack particularly stealthy.

## Example
We will be using a book review application. The application allows users to add new books via a web page (`add.php`). Users are prompted to provide details about the book they wish to add to the database. You can access the app at `http://MACHINE_IP/second/add.php`[.](http://machine_ip/case1.) The data collected includes the `SSN`, `book_name`, and `author`. Let's consider adding a book with the following details: **SSN: UI00012**, **Book Name: Intro to PHP**, **Author: Tim**. 

This information is input through a form on the `add.php` page, and upon submission, it is stored in the **BookStore** database as shown below:
	![](Pasted%20image%2020241207194946.png)
As we know, Second-Order SQL injection is notably challenging to identify. Unlike traditional SQL Injection, which exploits real-time processing vulnerabilities, it occurs when data previously stored in a database is later used in a SQL query. Detecting this vulnerability often requires understanding how data flows through the application and is reused, necessitating a deep knowledge of the backend operations.

### Code Analysis
Consider the PHP code snippet used in our application for adding books:
```php
if (isset($_POST['submit'])) { $ssn = $conn->real_escape_string($_POST['ssn']); $book_name = $conn->real_escape_string($_POST['book_name']); $author = $conn->real_escape_string($_POST['author']); $sql = "INSERT INTO books (ssn, book_name, author) VALUES ('$ssn', '$book_name', '$author')"; if ($conn->query($sql) === TRUE) { echo "<p class='text-green-500'>New book added successfully</p>"; } else { echo "<p class='text-red-500'>Error: " . $conn->error . "</p>"; } }
```
