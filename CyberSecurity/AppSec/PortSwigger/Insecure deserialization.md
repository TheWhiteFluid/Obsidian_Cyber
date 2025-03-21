https://portswigger.net/web-security/deserialization#what-is-serialization
https://hacktricks.boitatech.com.br/pentesting-web/deserialization

# Summary
**Serialization** is the process of converting complex data structures, such as objects and their attributes, into a flatter format that can be sent and stored. This format preserves the state of the object and its data. Once serialized, the data can be:
- Written to a file
- Stored in a database
- Transmitted over a network

**Deserialization** is the reverse process - converting the serialized, flat data format back into a functional object that the application can use. During this process, the serialized data controls:
- What type of object is instantiated
- The values assigned to the object's attributes

**Insecure deserialization** occurs when an application deserializes untrusted data without sufficient verification. This creates a critical vulnerability that can lead to:
- Remote code execution (RCE)
- Authentication bypasses
- Authorization bypasses
- Object and data structure manipulation

These vulnerabilities are particularly dangerous because they can enable an attacker to:
1. Manipulate serialized objects
2. Pass malicious data into the application code
3. Achieve a variety of attacks depending on the application logic

## Serialization Formats
- **Binary Formats**
    - Java serialization (using ObjectInputStream)
    - .NET BinaryFormatter
    - Python pickle
- **Structured Text Formats**
    - JSON
    - XML
    - YAML

### Indicators of Potential Vulnerabilities:
- Base64-encoded data being transmitted
- Suspicious parameter names (e.g., "data", "object", "serialized", "marshal")
- Hidden form fields containing structured data
- Cookies with serialized data
- File extensions specific to serialization (.pkl, .ser, etc.)

### Common Signatures:
- Java: Strings containing `rO0` (Base64 of serialized Java objects)
- .NET: Format markers in serialized data
- PHP: Serialized data starting with characters like `a:`, `O:`, or `s:`
- Python: Use of pickle or marshal modules


## Exploitation Techniques

### 1. **Modifying Serialized Objects:**
- Changing attribute values to manipulate application logic
- Tampering with access control data
- Modifying session tokens

### 2. **Gadget Chains:**
- A series of connected method calls that occur during deserialization
- Pre-built chains like ysoserial for Java and ysoserial.net for .NET
- Can lead to command execution even without custom code

### 3. Format-Specific Attacks:
- **PHP**: Magic methods like `__wakeup()` and `__destruct()`
- **Java**: Exploiting `readObject()` implementations
- **Python**: Leveraging the unsafe nature of pickle
- **.NET**: Abusing TypeNameHandling in JSON.NET


## Testing for Deserialization Vulnerabilities

**Manual Testing Approaches:**
1. Identify serialized data in the application
2. Attempt to decode and modify the data
3. Test for error-based detection (introduce invalid data and observe responses)
4. Use known gadget chains with tools like ysoserial

**Automated Testing:**
- Dynamic scanning tools with deserialization modules
- Static code analysis to detect unsafe deserialization patterns
- Custom scripts to test specific serialization implementations


## Prevention Measures

### 1. Architectural Defenses
- Never deserialize untrusted data
- Use data formats that don't support object serialization (e.g., JSON without custom resolvers)
- Implement integrity checks (cryptographic signatures for serialized data)

### 2. Implementation Defenses
- Input validation before deserialization
- Type constraints during deserialization
- Implementing deserialization filters (whitelisting classes)

### 3. Language-Specific Defenses
- **Java**: Using ValidatingObjectInputStream, SerialKiller, or RASP solutions
- **PHP**: Avoiding unserialize() on user input or using safe alternatives like JSON
- **.NET**: Avoiding BinaryFormatter, NetDataContractSerializer, or implementing SerializationBinder
- **Python**: Using alternatives to pickle like JSON, or implementing restrictions

### 4. Additional Security Controls
- Implementing principle of least privilege
- Using application firewalls that can detect serialized objects
- Network segregation to limit the impact of successful exploits


## 1. Modifying serialized objects
This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in using your own credentials. Notice that the post-login `GET /my-account` request contains a session cookie that appears to be URL and Base64-encoded.
2. Use Burp's Inspector panel to study the request in its decoded form. Notice that the cookie is in fact a serialized PHP object. The `admin` attribute contains `b:0`, indicating the boolean value `false`. Send this request to Burp Repeater.
3. In Burp Repeater, use the Inspector to examine the cookie again and change the value of the `admin` attribute to `b:1`. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
4. Send the request. Notice that the response now contains a link to the admin panel at `/admin`, indicating that you have accessed the page with admin privileges.
5. Change the path of your request to `/admin` and resend it. Notice that the `/admin` page contains links to delete specific user accounts. Change the path of your request to `/admin/delete?username=carlos` and send the request to solve the lab.


**Workflow**: