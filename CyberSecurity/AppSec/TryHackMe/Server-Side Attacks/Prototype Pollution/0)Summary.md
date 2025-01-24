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