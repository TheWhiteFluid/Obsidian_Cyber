
ORM is a programming technique that facilitates data conversion between incompatible systems using object-oriented programming languages. It allows developers to interact with a database using the programming language's native syntax, making data manipulation more intuitive and reducing the need for extensive SQL queries. ORM is particularly beneficial when complex data interactions are required, as it simplifies database access and promotes code reusability.
	![](Pasted%20image%2020250110154927.png)
ORM serves as a bridge between the object-oriented programming model and the relational database model. The primary purpose of an ORM is to abstract the database layer, allowing developers to work with objects rather than tables and rows. This abstraction layer helps in:
- **Reducing boilerplate code**: ORM reduces the need for repetitive code by automatically generating SQL queries based on object operations.
- **Increasing productivity**: Developers can focus on the business logic without worrying about database interactions.
- **Ensuring consistency**: ORM frameworks consistently handle database operations, reducing the risk of errors.
- **Enhancing maintainability**: Changes to the database schema are easier to manage, as they can be reflected in the object model without extensive code modifications.


## Commonly Used ORM Frameworks

### **Doctrine (PHP)**
Doctrine is a powerful and flexible ORM framework for PHP. It is particularly popular in the Symfony framework but can be used independently. Doctrine provides a comprehensive set of tools for database interactions, including a query builder, schema management, and an object-oriented query language. Its ability to map complex object structures to database schemas makes it a favorite among PHP developers.

### **Hibernate (Java)**
Hibernate is a robust and mature ORM framework for Java applications. It simplifies the mapping of Java classes to database tables and provides powerful data retrieval and manipulation capabilities through its Hibernate Query Language (HQL). Hibernate supports various database management systems and is known for its performance optimisation features, such as caching and lazy loading.

### **SQLAlchemy (Python)**
SQLAlchemy is a versatile and powerful ORM for Python. It offers an SQL toolkit and an ORM system that allows developers to use raw SQL when needed while still providing the benefits of an ORM. SQLAlchemy's flexibility and modular architecture make it suitable for a wide range of applications, from small scripts to large-scale enterprise systems.

### **Entity Framework (C#)**
Entity Framework is Microsoft's ORM framework for .NET applications. It enables developers to work with relational data using domain-specific objects, eliminating the need for most data-access code that developers typically need to write. Entity Framework supports a variety of database providers and integrates seamlessly with other .NET technologies.

### **Active Record (Ruby on Rails)**
Active Record is the default ORM for Ruby on Rails applications. It follows the Active Record design pattern, which means that each table in a database corresponds to a class, and each row in the table corresponds to an instance of that class. Active Record simplifies database interactions by providing a rich set of methods for querying and manipulating data.


## How ORM Works
### **Mapping Between Objects in Code and Database Tables**
ORM is a technique that simplifies data interaction in an application by mapping objects in code to database tables. In PHP, this process involves defining classes that represent database tables and their relationships. Each class property corresponds to a column in the table, and each class instance represents a row.

For instance, using Laravel's Eloquent ORM, you might define a model class like this:

```php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;
class User extends Model
{
    protected $table = 'users';
    protected $fillable = [
        'name', 'email', 'password',
    ];
    // Other Eloquent model configurations can go here...
}
```

In this example, the `User` class maps to the `users` table in the database, with properties corresponding to columns. Eloquent ORM handles the translation between these object representations and the underlying SQL queries, allowing developers to manipulate database records using object-oriented syntax.

### Common ORM Operations (Create, Read, Update, Delete)
ORM frameworks streamline common database operations, often referred to as CRUD operations:

- **Create**: Creating new records in the database involves instantiating a new model object, setting its properties, and saving it to the database.

```php
use App\Models\User;

// Create a new user
$user = new User();
$user->name = 'Admin';
$user->email = 'admin@example.com';
$user->password = bcrypt('password'); 
$user->save();
```

This code creates a new user and saves it to the database. The save method prepares the entity for insertion and executes the SQL INSERT statement to add the new record to the users table. The `bcrypt()` function is used to securely hash the password before saving it.

- **Read**: Reading records from the database involves retrieving data using various Eloquent methods.
```php
use App\Models\User;

// Find a user by ID
$user = User::find(1);

// Find all users
$allUsers = User::all();

// Find users by specific criteria
$admins = User::where('email', 'admin@example.com')->get();
```

This code demonstrates different ways to retrieve records from the database. The function `find(1)` retrieves the user with ID 1 by executing a SELECT SQL statement. The function `all()` retrieves all users by executing a `SELECT * FROM users` SQL statement. The clause `where('email', 'admin@example.com')->get()` retrieves users with the specified email by executing a `SELECT * FROM users WHERE email = 'admin@example.com'` SQL statement.
	![](Pasted%20image%2020250110204352.png)

Similar to the create and read operations, the **update** and **delete** functionalities follow a straightforward approach using Laravel's Eloquent ORM. For updates, you retrieve the existing record, modify its properties, and save the changes. For deletions, you retrieve the record and call the delete method to remove it from the database. Eloquent handles the preparation and execution of the corresponding SQL statements, making database operations simple and intuitive.


## SQL Injection vs. ORM Injection
SQL injection and ORM injection are both techniques used to exploit vulnerabilities in database interactions, but they target different levels of the stack:

- **SQL injection**: Targets raw SQL queries, allowing attackers to manipulate SQL statements directly. This is typically achieved by injecting malicious input into query strings. The injection part in the following query, `OR '1'='1`, always evaluates to true, allowing attackers to bypass authentication:

```php
SELECT * FROM users WHERE username = 'admin' OR '1'='1';
```

| **Aspect**         | **SQL Injection  <br>**                                             | **ORM Injection**                                                                                 |
| ------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Level of injection | Targets raw SQL queries directly                                    | Targets the ORM framework's query construction                                                    |
| Complexity         | More straightforward, as it manipulates raw SQL                     | Requires understanding of ORM internals and methods                                               |
| Detection          | Easier to detect with traditional WAFs and query logs               | Harder to detect, as payloads are within ORM methods                                              |
| Mitigation         | Use of prepared statements, parameterised queries, input validation | Proper ORM configuration, application-level input validation, ORM features enforcing query safety |

## Configuring the Environment
Since we are using Laravel in this project, we will briefly explain how to configure Eloquent ORM (Laravel-based). Eloquent ORM is the default ORM included with Laravel, which provides a beautiful, simple `Active Record` implementation for working with your database. First, we need to install Laravel using Composer. Open your terminal and run the command `composer create-project --prefer-dist laravel/laravel thm-project`

**Configure Database Credentials**  
Next, we need to configure our database credentials. Laravel uses the `.env` file to store environment variables, including database credentials. Open the `.env` file in the root of your Laravel project and update the following lines with your database details:

```php
DB_CONNECTION = mysql
DB_HOST=127.0.0.1 
DB_PORT=3306
DB_DATABASE = your_database_name 
DB_USERNAME = your_database_user 
DB_PASSWORD = your_database_password
```

**Setting up Migrations**
Migrations are like version control for your database, allowing you to easily modify and share the database schema. Laravel’s migration system is an essential part of the framework and simplifies the management of database changes.

To create a migration, we can use the `Artisan` command-line tool that comes with Laravel. You can run the command `php artisan make:migration create_users_table --create=users` to generate a migration for the `users` table:

This command generates a migration file in the database/migrations directory. The migration file contains methods to define the structure of the `users` table.
```php
<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateUsersTable extends Migration
{
    public function up()
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->timestamps();
        });
    }
    public function down()
    {
        Schema::dropIfExists('users');
    }
}
```

In the above code, the `up()` method defines the structure of the `users` table. It includes columns for ID, name, email, password, and timestamps. Conversely, the `down()` method drops the `users` table if the migration is rolled back.

After defining the migration, run the command `php artisan migrate` to apply the migration and create the `users` table in the database. This command will execute the `up()` method in the migration file and create the `users` table with the specified columns in your database.

In the context of ORM, migrations simplify the process of mapping database tables to application models. They enable developers to focus on writing clean, maintainable code while ensuring that the underlying database schema supports the application's data requirements. However, from a red team perspective, improperly configured migrations and weak implementations can lead to vulnerabilities like ORM injection. Hackers often exploit these weaknesses to manipulate database queries and gain unauthorised access to sensitive data. Therefore, it is crucial to use migrations effectively to enforce strong, secure database schema designs and ensure robust ORM configurations to prevent such security flaws.

