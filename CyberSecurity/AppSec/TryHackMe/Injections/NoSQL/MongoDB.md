Much like MySQL, MariaDB, or PostgreSQL, MongoDB is another database where you can store data in an ordered way. MongoDB allows you to retrieve subsets of data in a quick and structured form. If you are familiar with relational databases, you can assume MongoDB works similarly to any other database. The major exception is that the information isn't stored on tables but rather in documents.

You can think of these documents as a simple dictionary structure where key-value pairs are stored. In a way, they are very similar to what you would call a record on a traditional relational database, but the information is just stored differently. For example, let's say we are creating a web application for the HR department, and we would like to store basic employee information. You would then create a document for each employee containing the data in a format that looks like this:

{"_id" : ObjectId("5f077332de2cdf808d26cd74"), "username" : "lphillips", "first_name" : "Logan", "last_name" : "Phillips", "age" : "65", "email" : "lphillips@example.com" }

As you see, documents in MongoDB are stored in an associative array with an arbitrary number of fields.

MongoDB allows you to group multiple documents with a similar function together in higher hierarchy structures called collections for organizational purposes. Collections are the equivalent of tables in relational databases. Continuing with our HR example, all the employee's documents would be conveniently grouped in a collection called "people" as shown in the diagram below.
	![](Pasted%20image%2020241214205821.png)

Multiple collections are finally grouped in databases, which is the highest hierarchical element in MongoDB. In relational databases, the database concept groups tables together. In MongoDB, it groups related collections.
	![](Pasted%20image%2020241214205911.png)

## Querying the Database
As with any database, a special language is used to retrieve information from the database. Just as relational databases use some variant of SQL, non-relational databases such as MongoDB use NoSQL. In general terms, NoSQL refers to any way of querying a database that is not SQL, meaning it may vary depending on the database used.

With MongoDB, queries use a structured associative array that contains groups of criteria to be met to filter the information. These filters offer similar functionality to a WHERE clause in SQL and offer operators the ability to build complex queries if needed.

![](Pasted%20image%2020241214210436.png)

If we wanted to build a filter so that only the documents where the last_name is "Sandler" are retrieved, our filter would look like this:  

`['last_name' => 'Sandler']`  | As a result, this query only retrieves the second document.

If we wanted to filter the documents where the gender is male, and the last_name is Phillips, we would have the following filter:

`['gender' => 'male', 'last_name' => 'Phillips']` | This would only return the first document.

If we wanted to retrieve all documents where the age is less than 50, we could use the following filter:

``['age' => ['$lt'=>'50']]``

This would return the second and third documents. Notice we are using the **$lt** operator in a nested array. Operators allow for more complex filters by nesting conditions. A complete reference of possible operators can be found on the following link: [MongoDB Operator Reference](https://docs.mongodb.com/manual/reference/operator/query/)

## Injection
The root cause of an injection attack is that improper concatenation of untrusted user input into a command can allow an attacker to alter the command itself. With SQL injection, the most common approach is to inject a single or double quote, that terminates the current data concatenation and allows the attacker to modify the query. The same approach applies to NoSQL Injection. If untrusted user input is directly added to the query, we have the opportunity to modify the query itself. However, with NoSQL Injection, even if we can't escape the current query, we still have the opportunity to manipulate the query itself. Therefore, there are two main types of NoSQL Injection:

- **Syntax Injection** - This is similar to SQL injection, where we have the ability to break out of the query and inject our own payload. The key difference to SQL injection is the syntax used to perform the injection attack.
- **Operator Injection**—Even if we can't break out of the query, we could potentially inject a NoSQL query operator that manipulates the query's behaviour, allowing us to stage attacks such as authentication bypasses.

In this room, our main focus will be on Operator Injection and the different ways it can be leveraged. This is because it is not as common to find Syntax Injection cases as most libraries used to create the queries apply filters that prevent you from injection into the syntax. However, since user input can vary, these same filters can often be vulnerable to Operator Injection.

## How to Inject NoSQL
When looking at how NoSQL filters are built, bypassing them to inject any payload might look impossible, as they rely on creating a structured array. Unlike SQL injection, where queries were normally built by simple string concatenation, NoSQL queries require nested associative arrays. From an attacker's point of view, this means that to inject NoSQL, one must be able to inject arrays into the application.

Luckily for us, many server-side programming languages allow passing array variables by using a special syntax on the query string of an HTTP Request. For the purpose of this example, let's focus on the following code written in PHP for a simple login page:

```php
<?php
$con = new MongoDB\Driver\Manager("mongodb://localhost:27017");


if(isset($_POST) && isset($_POST['user']) && isset($_POST['pass'])){
        $user = $_POST['user'];
        $pass = $_POST['pass'];

        $q = new MongoDB\Driver\Query(['username'=>$user, 'password'=>$pass]);
        $record = $con->executeQuery('myapp.login', $q );
        $record = iterator_to_array($record);

        if(sizeof($record)>0){
                $usr = $record[0];

                session_start();
                $_SESSION['loggedin'] = true;
                $_SESSION['uid'] = $usr->username;

                header('Location: /sekr3tPl4ce.php');
                die();
        }
}
header('Location: /?err=1');

?>
```

The web application is making a query to MongoDB, using the "**myapp**" database and "**login**" collection, requesting any document that passes the filter `['username'=>$user, 'password'=>$pass]`, where both `$user` and `$pass` are obtained directly from HTTP POST parameters. Let's take a look at how we can leverage Operator Injection in order to bypass authentication.

If somehow we could send an array to the $user and $pass variables with the following content:  
`$user = ['$ne'=>'xxxx']` 
`$pass = ['$ne'=>'yyyy']` 

The resulting filter would end up looking like this:  
`['username'=>['$ne'=>'xxxx'], 'password'=>['$ne'=>'yyyy']]`

We could trick the database into returning any document where the username isn't equal to '**xxxx**,' and the password isn't equal to '**yyyy**'. This would probably return all documents in the login collection. As a result, the application would assume a correct login was performed and let us into the application with the privileges of the user corresponding to the first document obtained from the database.

The problem that remains unsolved is how to pass an array as part of a POST HTTP Request. It turns out that PHP and many other languages allow you to pass an array by using the following notation on the POST Request Body:

`user[$ne]=xxxx&pass[$ne]=yyyy`