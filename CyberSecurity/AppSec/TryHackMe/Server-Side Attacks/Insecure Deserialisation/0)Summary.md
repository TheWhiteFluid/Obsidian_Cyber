Insecure deserialisation exploits occur when an application trusts serialised data enough to use it without validating its authenticity. This trust can lead to disastrous outcomes as attackers manipulate serialised objects to achieve remote code execution, escalate privileges, or launch denial-of-service attacks. This type of vulnerability is prevalent in applications that serialise and deserialise complex data structures across various programming environments, such as Java, .NET, and PHP, which often use serialisation for remote procedure calls, session management, and more.


## Serialisation
In programming, serialisation is the process of transforming an object's state into a human-readable or binary format (or a mix of both) that can be stored or transmitted and reconstructed as and when required. This capability is essential in applications where data must be transferred between different parts of a system or across a network, such as in web-based applications.	
	![](Pasted%20image%2020250116002125.png)
```php
<?php

$noteArray = array("title" => "My THM Note", "content" => "Welcome to THM!");

// Converting the note into a storable format
$serialisedNote = serialize($noteArray);

// Saving the serialised note to a file
file_put_contents('note.txt', $serialisedNote);  
?>```

The following output shows the serialised string in the `note.txt` file, which includes details of the note's structure and content. It’s stored in a way that can be easily saved or transmitted.
	**Serialised Note**: `a:2:{s:5:"title";s:12:"My THM Note";s:7:"content";s:12:"Welcome to THM!";}`

## Deserialisation
Deserialisation is the process of converting the formatted data back into an object. It's crucial for retrieving data from files, databases, or across networks, restoring it to its original state for usage in applications.
	![](Pasted%20image%2020250116002812.png)

Following our previous example, here's how you might deserialise the note data in PHP:
```php
<?php

// Reading the serialised note from the file
$serialisedNote = file_get_contents('note.txt'); 

// Converting the serialised string back into a PHP array
$noteArray = unserialize($serialisedNote);  

echo "Title: " . $noteArray['title'] . "<br>";
echo "Content: " . $noteArray['content'];
?>
```

This code reads the serialised note from a file and converts it back into an array, effectively reconstructing the original note. Discussing serialisation also necessitates a conversation about security. Like you wouldn’t want someone tampering with your school bag, insecure deserialisation can lead to significant security vulnerabilities in software applications. Attackers might alter serialised objects to execute unauthorised actions or steal data.

## Specific Incidents 
Some specific incidents where serialisation vulnerabilities played a critical role in cyber security breaches or attacks, highlighting the importance of secure serialisation practices. These examples illustrate how attackers exploit serialisation flaws to achieve remote code execution, data leakage, and more.

**Log4j Vulnerability CVE-2021-44228**  
- **Incident**: The [Log4j vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2021-44228), or Log4Shell, is a critical security flaw found in the Apache Log4j 2 library, a widely used logging library in Java applications. The vulnerability allows remote attackers to execute arbitrary code on affected systems by exploiting the library's insecure deserialisation functionality. If you want to learn more about this vulnerability, check out the [Solar, exploiting log4j](https://tryhackme.com/r/room/solar) room.
- **Impact:** The vulnerability facilitated remote code execution, enabling attackers to execute arbitrary commands on affected systems. This allowed attackers to compromise critical infrastructure, leading to unauthorised access to sensitive data, service disruptions, and potential supply chain attacks.

**WebLogic Server Remote Code Execution CVE-2015-4852**
- **Incident**: This vulnerability was related to how the [Oracle WebLogic Server](https://www.oracle.com/security-alerts/alert-cve-2015-4852.html) deserialised data was sent to the T3 protocol. Attackers could send maliciously crafted objects to the server, which, when deserialised, led to remote code execution.
- **Impact**: This vulnerability was widely exploited to gain unauthorised access to systems, deploy ransomware, or steal data. It affected all versions of the WebLogic Server that had not disabled the vulnerable service or patched the issue.

**Jenkins Java Deserialisation CVE-2016-0792**
- **Incident**: [Jenkins](https://www.tenable.com/plugins/nessus/89034), a popular automation server used in software development, experienced a critical vulnerability involving Java deserialisation. Attackers could send crafted serialisation payloads to the Jenkins CLI, which, when deserialised, could allow arbitrary code execution.
- **Impact**: This allowed attackers to execute shell commands, potentially taking over the Jenkins server, which often has broad access to a software development environment, including source code, build systems, and potentially deployment environments.


## Serialisation Formats
While different programming languages may use varying keywords and functions for serialisation, the underlying principle remains consistent. As we know, serialisation is the process of converting an object's state into a format that can be easily stored or transmitted and then reconstructed later. Whether Java, Python, .NET, or PHP, each language implements serialisation to accommodate specific features or security measures inherent to its environment. 
	![](Pasted%20image%2020250116004405.png)

Unlike other common vulnerabilities that exploit the immediate processing of user inputs, insecure deserialisation problems involve a deeper interaction with the application’s core logic, often manipulating the fundamental behaviour of its components.  

Now, let's explore how serialisation is explicitly handled in different languages, exploring its functionality, syntax, and unique features.

### **PHP**
In PHP, serialisation is accomplished using the `serialize()` function. This function converts a PHP object or array into a byte stream representing the object's data and structure. The resulting byte stream can include various data types, such as strings, arrays, and objects, making it unique. To illustrate this, let's consider a notes application where users can save and retrieve their notes. We'll create a PHP class called **Notes** to represent each note and handle serialisation and deserialisation.

In our Notes application, when a user saves a note, we serialise the Notes class object using PHP's `serialize()` function. This converts the object into a string representation that can be stored in a file or database. Let's take a look at the following code snippet that serialises the Notes class object:

```php
$note = new Notes("Welcome to THM");
$serialized_note = serialize($note);
```

For example, if you enter the string **Welcome to THM**, it will generate the output `O:5:"Notes":1:{s:7:"content";s:14:"Welcome to THM";}`
	![](Pasted%20image%2020250116005511.png)
- `O:5:"Notes":1:`: This part indicates that the serialised data represents an object of the class **Notes**, which has one property.
- `s:7:"content"`: This represents the property name "**content**" with a length of 7 characters. In serialised data, strings are represented with `s` followed by the length of the string and the string in double quotes. Integers are represented with `i` followed by the numeric value without quotes.
- `s:14:"Welcome to THM"`: This is the value of the **content** property, with a length of 14 characters.

####  Magic Methods
- `__sleep()`: This method is called on an object before serialisation. It can clean up resources, such as database connections, and is expected to return an array of property names that should be serialised.
- `__wakeup()`: This method is invoked upon deserialisation. It can re-establish any connections that the object might need to operate correctly.
- `__serialize()`: As of PHP 7.4, this method enables you to customise the serialisation data by returning an array representing the object's serialised form.
- `__unserialize()`: This counterpart to `__serialize()` allows for customising the restoration of an object from its serialised data.

### **Python**
Python uses a module called **Pickle** to serialise and deserialise objects. This module converts a Python object into a byte stream (and vice versa), enabling it to be saved to a file or transmitted over a network. Pickling is a powerful tool for Python developers because it handles almost all types of Python objects without needing any manual handling of the object's state. We will follow the same notes application in Python as in PHP. Here is the code snippet from the `app.py` class:

```python
import pickle
import base64

...
serialized_data = request.form['serialized_data']
notes_obj = pickle.loads(base64.b64decode(serialized_data))
message = "Notes successfully unpickled."
...

elif request.method == 'POST':
    if 'pickle' in request.form:
        content = request.form['note_content']
        notes_obj.add_note(content)
        pickled_content = pickle.dumps(notes_obj)
        serialized_data = base64.b64encode(pickled_content).decode('utf-8')
        binary_data = ' '.join(f'{x:02x}' for x in pickled_content)
        message = "Notes pickled successfully."
```

**Pickling Process**
- **Creating a Notes class**: This class manages a list of notes. It provides methods to add a note and retrieve all notes, making it easy to manage the application's state.
- **Serialisation (Pickling)**: When a user submits a note, the Notes class instance (including all notes) is serialised using `pickle.dumps()`. This function transforms the Python object into a binary format that Python can later turn back into an object.

**Displaying the Serialised Data (Base64 Encoding)**
- **Why use base64**: Serialised data is binary and not safe for display in all environments. Binary data can contain bytes that may interfere with communication protocols (like HTTP). Base64 is an encoding scheme that converts binary data into plain text. It uses only readable characters, making it safe for transmission over channels that do not support binary data.
- **Encoding process**: After serialising the `Notes` object, the binary data is encoded into a base64 string using `base64.b64encode()`. This string is safe to display in the HTML and easily stored or transmitted.

**Deserialisation (Unpickling)**
- **Base64 decoding**: When unpickling, the base64 string is first decoded back into binary format using `base64.b64decode()`.
- **Unpickling**: The binary data is then passed to `pickle.loads()`, which reconstructs the original Python object from the binary stream.

![](Pasted%20image%2020250116011158.png)

- **Pickling**: When this string is pickled, it is converted into a binary format that is not human-readable. This binary format contains information about the data type, the data itself, and other necessary metadata to reconstruct the object.
- **Base64 encoding**: The binary form of the pickled data is then encoded into a Base64 string, which might look something like `gASVIQAAAAAAAACMBFdlbGNvbWXCoGFkZYFdcQAu`

Beyond these two languages, serialisation is a common feature across various programming environments, each with unique implementations and libraries. In Java, object serialisation is facilitated through the `Serializable` interface, allowing objects to be converted into byte streams and vice versa, which is essential for network communication and data persistence. For .NET, serialisation has evolved significantly over the years. Initially, `BinaryFormatter` was commonly used for binary serialisation; however, its use is now discouraged due to security concerns. Modern .NET applications typically use `System.Text.Json` for JSON serialisation, or **System.Xml.Serialization** for XML tasks, reflecting a shift towards safer, more standardised data interchange formats. Ruby offers simplicity with its `Marshal` module, which is renowned for serialising and deserialising objects, and for more human-readable formats, it often utilises YAML. Each language’s approach to serialisation reflects its usage contexts and security considerations, highlighting the importance of understanding and properly implementing serialisation to ensure the integrity and security of data across web applications.

## Identification
