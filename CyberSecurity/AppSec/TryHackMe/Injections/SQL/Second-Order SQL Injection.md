Second-order SQL injection, also known as stored SQL injection, exploits vulnerabilities where user-supplied input is saved and subsequently used in a different part of the application, possibly after some initial processing. This type of attack is more insidious because the malicious SQL code does not need to immediately result in a SQL syntax error or other obvious issues, making it harder to detect with standard input validation techniques. The injection occurs upon the second use of the data when it is retrieved and used in a SQL command, hence the name "**Second Order**".
	![](Pasted%20image%2020241207194811.png)

*Impact:*
The danger of Second-Order SQL Injection lies in its ability to bypass typical front-end defenses like basic input validation or sanitization, which only occur at the point of initial data entry. Since the payload does not cause disruption during the first step, it can be overlooked until it's too late, making the attack particularly stealthy.

## Example
We will be using a book review application. The application allows users to add new books via a web page (`add.php`). Users are prompted to provide details about the book they wish to add to the database. You can access the app at `http://MACHINE_IP/second/add.php`[.](http://machine_ip/case1.) The data collected includes the `SSN`, `book_name`, and `author`. Let's consider adding a book with the following details: **SSN: UI00012**, **Book Name: Intro to PHP**, **Author: Tim**. 

This information is input through a form on the `add.php` page, and upon submission, it is stored in the **BookStore** database as shown below:
	![](Pasted%20image%2020241207194946.png)
As we know, Second-Order SQL injection is notably challenging to identify. Unlike traditional SQL Injection, which exploits real-time processing vulnerabilities, it occurs when data previously stored in a database is later used in a SQL query. Detecting this vulnerability often requires understanding how data flows through the application and is reused, necessitating a deep knowledge of the backend operations.

### **Code Analysis**
Consider the PHP code snippet used in our application for adding books:
```php
if (isset($_POST['submit'])) {

    $ssn = $conn->real_escape_string($_POST['ssn']);

    $book_name = $conn->real_escape_string($_POST['book_name']);

    $author = $conn->real_escape_string($_POST['author']);

    $sql = "INSERT INTO books (ssn, book_name, author) VALUES ('$ssn', '$book_name', '$author')";

    if ($conn->query($sql) === TRUE) {

        echo "<p class='text-green-500'>New book added successfully</p>";

    } else {

        echo "<p class='text-red-500'>Error: " . $conn->error . "</p>";

    }
}
```

The code uses the `real_escape_string()` method to escape special characters in the inputs. While this method can mitigate some risks of immediate SQL Injection by escaping single quotes and other SQL meta-characters, it does not secure the application against Second Order SQLi. The key issue here is the lack of parameterised queries, which is essential for preventing SQL injection attacks. When data is inserted using the `real_escape_string()` method, it might include payload characters that don't cause immediate harm but can be activated upon subsequent retrieval and use in another SQL query. For instance, inserting a book with a name like `Intro to PHP'; DROP TABLE books;--` might not affect the **INSERT** operation but could have serious implications if the book name is later used in another SQL context without proper handling.

Let's try adding another book with the SSN `test'`.
	![](Pasted%20image%2020241207235645.png)

Here we go, the SSN `test'` is successfully inserted into the database. The application includes a feature to update book details through an interface like `update.php`. This interface might display existing book details in editable form fields, retrieved based on earlier stored data, and then update them based on user input. The pentester would investigate whether the application reuses the data (such as `book_name`) that was previously stored and potentially tainted. Then, he would construct SQL queries for updating records using this potentially tainted data without proper sanitisation or parameterisation. By manipulating the update feature, the tester can see if the malicious payload added during the insertion phase gets executed during the update operation. If the application fails to employ proper security practices at this stage, the earlier injected payload `'; DROP TABLE books; --` could be activated, leading to the execution of a harmful SQL command like dropping a table. You can visit the page `http://10.10.114.83/second/update.php` to update any book details.
	![](Pasted%20image%2020241207235827.png)

Now, let's review the `update.php` code. The PHP script allows users to update book details within the **BookStore** database. Through the query structure, we will analyse a typical scenario where a penetration tester might look for SQL injection vulnerabilities, specifically focusing on how user inputs are handled and utilised in SQL queries.
```php
if ( isset($_POST['update'])) {
    $unique_id = $_POST['update'];
    $ssn = $_POST['ssn_' . $unique_id];
    $new_book_name = $_POST['new_book_name_' . $unique_id];
    $new_author = $_POST['new_author_' . $unique_id];

    $update_sql = "UPDATE books SET book_name = '$new_book_name', author = '$new_author' WHERE ssn = '$ssn'; INSERT INTO logs (page) VALUES ('update.php');";
..
...
```

The script begins by checking if the request method is POST and if the update button was pressed, indicating that a user intends to update a book's details. Following this, the script retrieves user inputs directly from the POST data:
```php
    $unique_id = $_POST['update'];
    $ssn = $_POST['ssn_' . $unique_id];
    $new_book_name = $_POST['new_book_name_' . $unique_id];
    $new_author = $_POST['new_author_' . $unique_id];
    ```

These variables (`ssn, new_book_name, new_author`) are then used to construct an SQL query for updating the specified book's details in the database:
```php
$update_sql = "UPDATE books SET book_name = '$new_book_name', author = '$new_author' WHERE ssn = '$ssn'; INSERT INTO logs (page) VALUES ('update.php');";
```

### **Payload**
We know that we can add or modify the book details based on their `ssn`. The normal query for updating a book might look like this:
```php
UPDATE books SET book_name = '$new_book_name', author = '$new_author' WHERE ssn = '123123';
```

However, the SQL command could be manipulated if an attacker inserts a specially crafted `ssn` value. For example, if the attacker uses the `ssn` value:
```php
12345'; UPDATE books SET book_name = 'Hacked'; --
```

When this value is used in the update query, it effectively ends the initial update command after `12345` and starts a new command. This would change the `book_name` of all entries in the books table to **Hacked**.

---------------------------------------------------------------------------

![](Pasted%20image%2020241208000910.png)

- **Initial Payload Insertion**: A new book is added with the payload `12345'; UPDATE books SET book_name = 'Hacked'; --` is inserted as the `ssn`. The semicolon (`;`) will be used to terminate the current SQL statement.

![total books in database with injection payload](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1715789331772)  

- **Malicious SQL Execution**: After that, when the admin or any other user visits the URL `http://10.10.114.83/second/update.php` and updates the book, the inserted payload breaks out of the intended SQL command structure and injects a new command that updates all records in the books table. Let's visit the page  `http://10.10.114.83/second/update.php page`, update the book name to anything, and click the **Update** button. The code will execute the following statement in the backend.
```php
UPDATE books SET book_name = 'Test', author = 'Hacker' WHERE ssn = '12345'; Update books set book_name ="hacked"; --'; INSERT INTO logs (page) VALUES ('update.php');
```

- **Commenting Out the Rest**: The double dash (`--`) is an SQL comment symbol. Anything following `--` will be ignored by the SQL server, effectively neutralising any remaining parts of the original SQL statement that could cause errors or reveal the attack. Once the above query is executed, it will change the name of all the books to **hacked**, as shown below:

![state of database after executing payload](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1715789376753)

*Note:* 
	As a penetration tester, examining how user inputs are stored and later utilised within SQL queries is crucial. This involves verifying that all forms of data handling are secure against such vulnerabilities, emphasising the importance of thorough testing and knowledge of security practices to safeguard against injection threats.



