In JavaScript, **inheritance** is a mechanism that allows one object to access properties and methods of another object. This is primarily achieved through the **prototype chain**, a fundamental concept in JavaScript's object-oriented programming.

**Prototype Chain:**
Every JavaScript object has an internal link to another object called its **prototype**. This prototype object may also have its own prototype, forming a chain until an object is reached with `null` as its prototype. This chain of prototypes is known as the **prototype chain**.

**How Inheritance Works:**
When you try to access a property or method on an object, JavaScript first looks for that property on the object itself. If it doesn't find it, it searches the object's prototype, then the prototype's prototype, and so on, traversing up the prototype chain until it either finds the property or reaches the end of the chain (i.e., `null`). If the property isn't found anywhere in the chain, JavaScript returns `undefined`.

**Creating Prototypes:**

In JavaScript, functions can serve as object constructors. When a function is used as a constructor with the `new` keyword, the newly created object inherits from the constructor's `prototype` property. This allows all instances created by that constructor to share properties and methods defined on the prototype.

```javascript
function Person(name) {
  this.name = name;
}

Person.prototype.greet = function() {
  console.log(`Hello, my name is ${this.name}`);
};

const alice = new Person('Alice');
alice.greet(); // Output: Hello, my name is Alice
```

In this example, `Person` is a constructor function. The `greet` method is defined on `Person.prototype`, so all instances of `Person` (like `alice`) have access to this method through the prototype chain.


## Javascript Basics
 Think of **objects** as building blocks that hold information. 
 **Inheritance** is like passing down traits from one object to another.
 **Functions** are like tools that can be used alone or as part of these objects. 
 Lastly, **classes** in JavaScript are like blueprints that help us make similar things easily. 

### **Objects**
﻿In JavaScript, objects are like containers that can hold different pieces of information. Imagine a social network profile as an object, where each profile has properties like name, age, and followers. You can represent this using curly braces and key-value pairs:

```javascript
let user = {
  name: 'Ben S',
  age: 25,
  followers: 200,
  DoB: '1/1/1990'
};
```

Here, the `user` is an object with properties such as `name`, `age`, and `followers`.  These properties store specific information about the user. Objects in JavaScript enable us to organise and manage related data, making them a fundamental concept in building dynamic and interactive applications.  

### **Classes**
In JavaScript, classes are like blueprints that help create multiple objects with similar structures and behaviours. Staying with our social network example, we can use a class to define a general user and a content creator. Classes provide a convenient way to organise and instantiate objects with shared characteristics.

```javascript
// Class for User 
class UserProfile {
  constructor(name, age, followers, dob) {
    this.name = name;
    this.age = age;
    this.followers = followers;
    this.dob = dob; // Adding Date of Birth
  }
}

// Class for Content Creator Profile inheriting from User 
class ContentCreatorProfile extends User {
  constructor(name, age, followers, dob, content, posts) {
    super(name, age, followers, dob);
    this.content = content;
    this.posts = posts;
  }
}

// Creating instances of the classes
let regularUser = new UserProfile('Ben S', 25, 1000, '1/1/1990');
let contentCreator = new ContentCreatorProfile('Jane Smith', 30, 5000, '1/1/1990', 'Engaging Content', 50);
 
```

Now, the `User` class includes the Date of Birth (dob) as part of its properties, and the `ContentCreatorProfile` class inherits this property. When creating instances of these classes, we can provide the Date of Birth and other details. As we can see, including the Date of Birth enhances the user profiles with additional information.

### **Prototype**
In JavaScript, every object is linked to a prototype object, and these prototypes form a chain commonly referred to as the **prototype chain**. The prototype serves as a template or blueprint for objects. When you create an object using a constructor function or a class, JavaScript automatically sets up a link between the object and its prototype. In the context of our social network example, let's illustrate how prototypes work:

```javascript
// Prototype for User 
let userPrototype = {
  greet: function() {
    return `Hello, ${this.name}!`;
  }
};

// User Constructor Function
function UserProfilePrototype(name, age, followers, dob) {
  let user = Object.create(userPrototype);
  user.name = name;
  user.age = age;
  user.followers = followers;
  user.dob = dob;
  return user;
}

// Creating an instance
let regularUser = UserProfilePrototype('Ben S', 25, 1000, '1/1/1990');

// Using the prototype method
console.log(regularUser.greet());
```

### Difference between Class and Prototype
Classes and prototypes in JS are two ways to achieve a similar goal: creating objects with behaviours and characteristics. Imagine you're building models of cars in your room. Using classes is like having a detailed blueprint or a set of instructions for each car model you want to develop. You follow the blueprint exactly to create each car, and all cars made from the exact blueprint are guaranteed to have the same features and behaviours. Classes in JavaScript work similarly; they provide a clear, structured way to create objects that share the same properties and methods, making them easy to understand and use.

On the other hand, prototypes are like having a basic car model and then customizing it by adding or modifying features directly on the car itself. With prototypes, you start with a simple object and then add behaviours to it by linking it to a prototype object that already has those behaviours. Objects created this way are linked through the prototype chain, allowing them to inherit behaviours from other objects. This method is more dynamic and flexible but can be harder to manage and understand than the structured approach of classes.

### **Inheritance**
In JavaScript, inheritance allows one object to inherit properties from another, creating a hierarchy of related objects. Continuing with our social network example, let's consider a more specific profile for a content creator. This new object can inherit properties from the general user profile, like `name` and `followers`, and add particular properties, such as `content` and `posts`.

``` Javascript
let user = {
  name: 'Ben S',
  age: 25,
  followers: 1000,
DoB: '1/1/1990'
};

// Content Creator Profile inheriting from User 
let contentCreatorProfile = Object.create(user);
contentCreatorProfile.content = 'Engaging Content';
contentCreatorProfile.posts = 50;
```

Here, `contentCreatorProfile` inherits properties from the user using `Object.create()`. Now, it has specific properties like `content` and `posts` and inherits `name`, `age`, and `followers` from the general user profile, as shown below.
	![](Pasted%20image%2020250125014427.png)
This way, inheritance helps create a more specialised object while reusing common properties from a parent object. JavaScript supports both classes and prototype-based inheritance.
- **Prototype-based Inheritance**: In JavaScript, every object has a prototype, and when you create a new object, you can specify its prototype. Objects inherit properties and methods from their prototype. You can use the `Object.create()` method to create a new object with a specified prototype, or you can directly modify the prototype of an existing object using its prototype property
- **Class-based Inheritance**: JavaScript also supports classes, which provide a more familiar syntax for defining objects and inheritance. Classes in JavaScript are just syntactical sugar over JavaScript's existing prototype-based inheritance. Under the hood, classes still use prototypes.


The diagram on the below represents the prototype-based inheritance in JS:
	![](Pasted%20image%2020250125014839.png)
- **Defining UserProfile Object**: We start by defining a generic `UserProfile` object that represents common properties shared by different types of profiles. In this example, `UserProfile` includes properties like email and password, which might be common to all user profiles.
- **Creating ContentCreatorProfile**: We create a specialised profile called `ContentCreatorProfile`. This profile is specific to content creators and may have additional properties or behaviours beyond those in a generic user profile. We achieve this by creating `ContentCreatorProfile` using `Object.create(UserProfile)`, which sets `UserProfile` as the prototype of `ContentCreatorProfile`.
- **Adding Additional Properties**: After creating ContentCreatorProfile, we add specific properties such as posts. This property is unique to `ContentCreatorProfile` and is not inherited from `UserProfile`.
- **Accessing Properties**: When accessing properties of `ContentCreatorProfile`, JavaScript first checks if the property exists directly on `ContentCreatorProfile`. If it doesn't find the property there, it looks up the prototype chain and checks if the property exists on `UserProfile`. If found, it returns the value from the prototype chain. So, `ContentCreatorProfile` inherits properties email and password from `UserProfile`, while also having its own unique property number of posts. This allows for a hierarchical structure where specialised profiles can inherit common properties from a generic profile while adding their specific attributes.
	![](Pasted%20image%2020250125014934.png)
The concept of prototypes plays a crucial role in implementing inheritance. Each object in JavaScript has a prototype, which serves as a blueprint for the object's properties and methods. In the above image, when we define a class like `UserProfile`, its prototype becomes the prototype of all instances created from it. This means that properties and methods defined in the `UserProfile` class are accessible to all instances of `UserProfile`. Additionally, JavaScript allows us to extend these prototypes dynamically, enabling inheritance through prototype chaining. For instance, subclasses like `ContentCreator`, `ContentDesigner`, and `Moderator` can extend the prototype of the `UserProfile` class to inherit its properties and methods. By leveraging prototypes, JavaScript provides a flexible and efficient mechanism for implementing inheritance, enabling code reuse and maintainability in object-oriented programming paradigms.

## How it works
Prototype pollution is a vulnerability that arises when an attacker manipulates an object's prototype, impacting all instances of that object. In JavaScript, where prototypes facilitate inheritance, an attacker can exploit this to modify shared properties or inject malicious behaviour across objects.

Prototype pollution, on its own, might not always present a directly exploitable threat. However, its true potential for harm becomes notably pronounced when it joins with other types of vulnerabilities, such as XSS and CSRF.

Let's assume, we have a basic prototype for `Person` with an `introduce` method. The attacker aims to manipulate the behaviour of the `introduce` method across all instances by altering the prototype.

```javascript
// Base Prototype for Persons
let personPrototype = {
  introduce: function() {
    return `Hi, I'm ${this.name}.`;
  }
};

// Person Constructor Function
function Person(name) {
  let person = Object.create(personPrototype);
  person.name = name;
  return person;
}

// Creating an instance
let ben = Person('Ben');
```

When we create a new object, `ben`, and call the `introduce` method, it displays `Hi, I'm Ben`, as shown in the following figure.
	![](Pasted%20image%2020250125015916.png)
What if an attacker injects malicious content into the introduce method for all instances using the `__proto__` property. In JavaScript, the `__proto__` property is a common way to access the prototype of an object, essentially pointing to the object from which it inherits properties and methods. Let's see, somehow, the attacker executes the following code using any attack vector like XSS, CSRF, etc.

```javascript
// Attacker's Payload
ben.__proto__.introduce=function(){console.log("You've been hacked, I'm Bob");}
console.log(ben.introduce()); 
```

- **Prototype Definition**: The Person prototype (personPrototype) is initially defined with a harmless `introduce` method, introducing the person.
- **Object Instantiation**: An instance of Person is created with the name `'Ben' (let ben = Person('Ben');)`.
- **Prototype Pollution Attack**: The attacker injects a malicious payload into the prototype's `introduce` method, changing its behaviour to display a harmful message.
- **Impact on Existing Instances**: As a result, even the existing instance (`ben`) is affected, and calling `ben.introduce()` now outputs the attacker's injected message.

This example shows how an attacker can alter the behaviour of shared methods across objects, potentially causing security risks. Preventing prototype pollution involves carefully validating input data and avoiding directly modifying prototypes with untrusted content.