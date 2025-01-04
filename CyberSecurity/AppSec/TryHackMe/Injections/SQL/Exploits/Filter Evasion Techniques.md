In advanced SQL injection attacks, evading filters is crucial for successfully exploiting vulnerabilities. Modern web applications often implement defensive measures to sanitise or block common attack patterns, making simple SQL injection attempts ineffective. As pentesters, we must adapt using more sophisticated techniques to bypass these filters. 

## Character Encoding
- **URL Encoding**: URL encoding is a common method where characters are represented using a percent (%) sign followed by their ASCII value in hexadecimal. For example, the payload `' OR 1=1--` can be encoded as `%27%20OR%201%3D1--`. This encoding can help the input pass through web application filters and be decoded by the database, which might not recognise it as malicious during initial processing.
- **Hexadecimal Encoding**: Hexadecimal encoding is another effective technique for constructing SQL queries using hexadecimal values. For instance, the query `SELECT * FROM users WHERE name = 'admin'` can be encoded as `SELECT * FROM users WHERE name = 0x61646d696e`. By representing characters as hexadecimal numbers, the attacker can bypass filters that do not decode these values before processing the input.
- **Unicode Encoding:** Unicode encoding represents characters using Unicode escape sequences. For example, the string `admin` can be encoded as `\u0061\u0064\u006d\u0069\u006e`. This method can bypass filters that only check for specific ASCII characters, as the database will correctly process the encoded input.

### Example
In this example, we explore how developers can implement basic filtering to prevent SQL injection attacks by removing specific keywords and characters from user input. However, we will also see how attackers can bypass these defences using character encoding techniques like URL encoding.

Here's the PHP code (`search_books.php`) that handles the search functionality:
```php
$book_name = $_GET['book_name'] ?? '';
$special_chars = array("OR", "or", "AND", "and" , "UNION", "SELECT");
$book_name = str_replace($special_chars, '', $book_name);
$sql = "SELECT * FROM books WHERE book_name = '$book_name'";
echo "<p>Generated SQL Query: $sql</p>";
$result = $conn->query($sql) or die("Error: " . $conn->error . " (Error Code: " . $conn->errno . ")");
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
...
..
```

Here's the Javascript code in the index.html page that provides the user interface for searching books:
```javascript
function searchBooks() {
const bookName = document.getElementById('book_name').value;
const xhr = new XMLHttpRequest();
xhr.open('GET', 'search_books.php?book_name=' + encodeURIComponent(bookName), true);
   xhr.onload = function() {
       if (this.status === 200) {
           document.getElementById('results').innerHTML = this.responseText;
```

In the above example, the developer has implemented a basic defence mechanism to prevent SQL injection attacks by removing specific SQL keywords, such as `OR`, `AND`, `UNION`, and `SELECT`. The filtering uses the `str_replace` function, which strips these keywords from the user input before they are included in the SQL query. This filtering approach aims to make it harder for attackers to inject malicious SQL commands, as these keywords are essential for many SQL injection payloads.

To bypass the filtering, we need to encode the input using URL encoding, which represents special characters and keywords in a way that the filter does not recognise and remove. Here is the example payload `1%27%20||%201=1%20--+`.  (`1' || 1=1 --'`)

The payload works because URL encoding represents the special characters and SQL keywords in a way that bypasses the filtering mechanism. When the server decodes the URL-encoded input, it restores the special characters and keywords, allowing the SQL injection to execute successfully. Using URL encoding, attackers can craft payloads that bypass basic input filtering mechanisms designed to block SQL injection. This demonstrates the importance of using more robust defences, such as parameterised queries and prepared statements, which can prevent SQL injection attacks regardless of the input's encoding.
	![](Pasted%20image%2020241210175706.png)
	
## No-Quote Allowed
No-Quote SQL injection techniques are used when the application filters single or double quotes or escapes.  
- **Using Numerical Values**: One approach is to use numerical values or other data types that do not require quotes. For example, instead of injecting `' OR '1'='1`, an attacker can use `OR 1=1` in a context where quotes are not necessary. This technique can bypass filters that specifically look for an escape or strip out quotes, allowing the injection to proceed.
- **Using SQL Comments**: Another method involves using SQL comments to terminate the rest of the query. For instance, the input `admin'--` can be transformed into `admin--`, where the `--` signifies the start of a comment in SQL, effectively ignoring the remainder of the SQL statement. This can help bypass filters and prevent syntax errors.
- **Using CONCAT() Function**: Attackers can use SQL functions like `CONCAT()` to construct strings without quotes. For example, `CONCAT(0x61, 0x64, 0x6d, 0x69, 0x6e)` constructs the string admin. The `CONCAT()` function and similar methods allow attackers to build strings without directly using quotes, making it harder for filters to detect and block the payload.

## No Spaces Allowed
When spaces are not allowed or are filtered out, various techniques can be used to bypass this restriction.
- **Comments to Replace Spaces**: One common method is to use SQL comments (`/**/`) to replace spaces. For example, instead of `SELECT * FROM users WHERE name = 'admin'`, an attacker can use `SELECT/**//*FROM/**/users/**/WHERE/**/name/**/='admin'`. SQL comments can replace spaces in the query, allowing the payload to bypass filters that remove or block spaces.
- **Tab or Newline Characters**: Another approach is using tab (`\t`) or newline (`\n`) characters as substitutes for spaces. Some filters might allow these characters, enabling the attacker to construct a query like `SELECT\t*\tFROM\tusers\tWHERE\tname\t=\t'admin'`. This technique can bypass filters that specifically look for spaces.
- **Alternate Characters**: One effective method is using alternative URL-encoded characters representing different types of whitespace, such as `%09` (horizontal tab), `%0A` (line feed), `%0C` (form feed), `%0D` (carriage return), and `%A0` (non-breaking space). These characters can replace spaces in the payload.

### Example
In this scenario, we have an endpoint, `http://10.10.80.101/space/search_users.php?username=?` that returns user details based on the provided username. 
	The developer has implemented filters to block common SQL injection keywords such as *OR*, *AND*, and *spaces* *(%20)* to protect against SQL injection attacks.

Here is the PHP filtering added by the developer.
```php
$special_chars = array(" ", "AND", "and" ,"or", "OR" , "UNION", "SELECT");
$username = str_replace($special_chars, '', $username);
$sql = "SELECT * FROM user WHERE username = '$username'";
```

If we use our standard payload `1%27%20||%201=1%20--+` (`1' || 1=1 --'`) on the endpoint, we can see that even through URL encoding, it is not working.
	![](Pasted%20image%2020241210180150.png)
The SQL query shows that the spaces are being omitted by code. To bypass these protections, we can use URL-encoded characters that represent different types of whitespace or line breaks, such as `%09` (horizontal tab), `%0A` (line feed). These characters can replace spaces and still be interpreted correctly by the SQL parser.

The original payload `1' OR 1=1 --` can be modified to use newline characters instead of spaces, resulting in the payload `1'%0A||%0A1=1%0A--%27+`. This payload constructs the same logical condition as `1' OR 1=1 --` but uses newline characters to bypass the space filter.

Now, if we access the endpoint through an updated payload, we can view all the details. 
	![](Pasted%20image%2020241210180321.png)

## Summary
To summarise, it is important to understand that no single technique guarantees a bypass when dealing with filters or Web Application Firewalls (WAFs) designed to prevent SQL injection attacks. However, here are some tips and tricks that can be used to circumvent these protections. This table highlights various techniques that can be employed to try and bypass filters and WAFs:

| **Scenario**                                               | **Description**                                                                                                  | **Example**                                                                                                 |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| *Keywords like SELECT are banned*                            | SQL keywords can often be bypassed by changing their case or adding inline comments to break them up.            | `SElEcT * FrOm users` or `SE/**/LECT * FROM/**/users`                                                       |
| *Spaces are banned*                                          | Using alternative whitespace characters or comments to replace spaces can help bypass filters.                   | `SELECT%0A*%0AFROM%0Ausers` or `SELECT/**/*/**/FROM/**/users`                                               |
| *Logical operators like AND, OR are banned*                | Using alternative logical operators or concatenation to bypass keyword filters.                                  | `username = 'admin' && password = 'password'` or `username = 'admin'/**/                                    |
| *Common keywords like UNION, SELECT are banned*            | Using equivalent representations such as hexadecimal or Unicode encoding to bypass filters.                      | `SELECT * FROM users WHERE username = CHAR(0x61,0x64,0x6D,0x69,0x6E)`                                       |
| *Specific keywords like OR, AND, SELECT, UNION are banned* | Using obfuscation techniques to disguise SQL keywords by combining characters with string functions or comments. | `SELECT * FROM users WHERE username = CONCAT('a','d','m','i','n')` or `SELECT/**/username/**/FROM/**/users` |
