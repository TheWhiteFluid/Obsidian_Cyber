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

### Architectural Defenses
- Never deserialize untrusted data
- Use data formats that don't support object serialization (e.g., JSON without custom resolvers)
- Implement integrity checks (cryptographic signatures for serialized data)

### Implementation Defenses
- Input validation before deserialization
- Type constraints during deserialization
- Implementing deserialization filters (whitelisting classes)

### Language-Specific Defenses
- **Java**: Using ValidatingObjectInputStream, SerialKiller, or RASP solutions
- **PHP**: Avoiding unserialize() on user input or using safe alternatives like JSON
- **.NET**: Avoiding BinaryFormatter, NetDataContractSerializer, or implementing SerializationBinder
- **Python**: Using alternatives to pickle like JSON, or implementing restrictions

### Additional Security Controls
- Implementing principle of least privilege
- Using application firewalls that can detect serialized objects
- Network segregation to limit the impact of successful exploits


# 1. Modifying serialized objects
This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in using your own credentials. Notice that the post-login `GET /my-account` request contains a session cookie that appears to be URL and Base64-encoded.
2. Use Burp's Inspector panel to study the request in its decoded form. Notice that the cookie is in fact a serialized PHP object. The `admin` attribute contains `b:0`, indicating the boolean value `false`. Send this request to Burp Repeater.
3. In Burp Repeater, use the Inspector to examine the cookie again and change the value of the `admin` attribute to `b:1`. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
4. Send the request. Notice that the response now contains a link to the admin panel at `/admin`, indicating that you have accessed the page with admin privileges.
5. Change the path of your request to `/admin` and resend it. Notice that the `/admin` page contains links to delete specific user accounts. Change the path of your request to `/admin/delete?username=carlos` and send the request to solve the lab.


**Workflow**:
1. Log in using your own credentials. Notice that the post-login `GET /my-account` request contains a session cookie that appears to be URL and Base64-encoded. 
	Use Burp's Inspector panel to study the request in its decoded form. Notice that the cookie is in fact a serialized PHP object. The `admin` attribute contains `b:0`, indicating the boolean value `false`. Send this request to Burp Repeater.
	![](Pasted%20image%2020250325050030.png)
2. .In Burp Repeater, use the Inspector to examine the cookie again and change the value of the `admin` attribute to `b:1`. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request. Send the request. Notice that the response now contains a link to the admin panel at `/admin`, indicating that you have accessed the page with admin privileges.
	![](Pasted%20image%2020250325050453.png)
3. Change the path of your request to `/admin` and resend it. Notice that the `/admin` page contains links to delete specific user accounts. Change the path of your request to `/admin/delete?username=carlos` and send the request to solve the lab.
	![](Pasted%20image%2020250325050905.png)


# 2. Modifying serialized data types
This lab uses a serialization-based session mechanism and is vulnerable to authentication bypass as a result. To solve the lab, edit the serialized object in the session cookie to access the `administrator` account. Then, delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
1. Log in using your own credentials. In Burp, open the post-login `GET /my-account` request and examine the session cookie using the Inspector to reveal a serialized PHP object. Send this request to Burp Repeater.
2. In Burp Repeater, use the Inspector panel to modify the session cookie as follows:
    - Update the length of the `username` attribute to `13`.
    - Change the username to `administrator`.
    - Change the access token to the integer `0`. As this is no longer a string, you also need to remove the double-quotes surrounding the value.
    - Update the data type label for the access token by replacing `s` with `i`.
    
    The result should look like this:
    `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`
3. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request. Send the request. Notice that the response now contains a link to the admin panel at `/admin`, indicating that you have successfully accessed the page as the `administrator` user.
4. Change the path of your request to `/admin` and resend it. Notice that the `/admin` page contains links to delete specific user accounts.  Change the path of your request to `/admin/delete?username=carlos` and send the request to solve the lab.

**Workflow**:
1. Log in using your own credentials. In Burp, open the post-login `GET /my-account` request and examine the session cookie using the Inspector to reveal a serialized PHP object. Send this request to Burp Repeater.
	![](Pasted%20image%2020250325052051.png)
2.  In Burp Repeater, use the Inspector panel to modify the session cookie as follows:
    - Update the length of the `username` attribute to `13`.
    - Change the username to `administrator`.
    - Change the access token to the integer `0`. As this is no longer a string, you also need to remove the double-quotes surrounding the value.
    - Update the data type label for the access token by replacing `s` with `i`
3. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request. Send the request. Notice that the response now contains a link to the admin panel at `/admin`, indicating that you have successfully accessed the page as the `administrator` user.
	![](Pasted%20image%2020250325052818.png)


# 3. Using application functionality to exploit insecure deserialization
This lab uses a serialization-based session mechanism. A certain feature invokes a dangerous method on data provided in a serialized object. To solve the lab, edit the serialized object in the session cookie and use it to delete the `morale.txt` file from Carlos's home directory.
You can log in to your own account using the following credentials: `wiener:peter` . 
You also have access to a backup account: `gregg:rosebud`

**Analysis**:
1. Log in to your own account. On the "My account" page, notice the option to delete your account by sending a `POST` request to `/my-account/delete`. 
2. In Burp Repeater, study the session cookie using the Inspector panel. Notice that the serialized object has an `avatar_link` attribute, which contains the file path to your avatar.
3. Edit the serialized data so that the `avatar_link` points to `/home/carlos/morale.txt`. Remember to update the length indicator. The modified attribute should look like this:
    `s:11:"avatar_link";s:23:"/home/carlos/morale.txt"`
4. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request. Change the request line to `POST /my-account/delete` and send the request. Your account will be deleted, along with Carlos's `morale.txt` file.

**Workflow**:
1. Log in to your own account. On the "My account" page, notice the option to delete your account by sending a `POST` request to `/my-account/delete`. 
	![](Pasted%20image%2020250326042154.png)
2. Edit the serialized data so that the `avatar_link` points to `/home/carlos/morale.txt`. Remember to update the length indicator. The modified attribute should look like this:
    `s:11:"avatar_link";s:23:"/home/carlos/morale.txt"`
    ![](Pasted%20image%2020250326043302.png)
3. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request. Change the request line to `POST /my-account/delete` and send the request. Your account will be deleted, along with Carlos's `morale.txt` file.


# 4. Arbitrary object injection in PHP
This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the `morale.txt` file **from Carlos's home directory.** You will need to obtain source code access to solve this lab. You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in to your own account and notice the session cookie contains a serialized PHP object. From the site map, notice that the website references the file `/libs/CustomTemplate.php`. Right-click on the file and select "Send to Repeater".
2. In Burp Repeater, notice that you can read the source code by appending a tilde (`~`) to the filename in the request line. In the source code, notice the `CustomTemplate` class contains the `__destruct()` magic method. This will invoke the `unlink()` method on the `lock_file_path` attribute, which will delete the file on this path.
3. In Burp Decoder, use the correct syntax for serialized PHP data to create a `CustomTemplate` object with the `lock_file_path` attribute set to `/home/carlos/morale.txt`. Make sure to use the correct data type labels and length indicators. The final object should look like this:
    `O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}`
4. Base64 and URL-encode this object and save it to your clipboard. Send a request containing the session cookie to Burp Repeater.
5. In Burp Repeater, replace the session cookie with the modified one in your clipboard. Send the request. The `__destruct()` magic method is automatically invoked and will delete Carlos's file.

**Workflow**:
1. Log in to your own account and notice the session cookie contains a serialized PHP object. From the site map, notice that the website references the file `/libs/CustomTemplate.php`. Right-click on the file and select "Send to Repeater".
	![](Pasted%20image%2020250326044144.png)
2. In Burp Repeater, notice that you can read the source code by appending a tilde (`~`) to the filename in the request line. In the source code, notice the `CustomTemplate` class contains the `__destruct()` magic method. This will invoke the `unlink()` method on the `lock_file_path` attribute, which will delete the file on this path.
	![](Pasted%20image%2020250326045946.png)
3.  In Burp Decoder, use the correct syntax for serialized PHP data to create a `CustomTemplate` object with the `lock_file_path` attribute set to `/home/carlos/morale.txt`. Make sure to use the correct data type labels and length indicators. The final object should look like this: `O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}`
	![](Pasted%20image%2020250326050910.png)
	**OR** 
	modifying cookie directly from inspector
	![](Pasted%20image%2020250326051036.png)
4. In Burp Repeater, replace the session cookie with the modified one in your clipboard. Send the request. The `__destruct()` magic method is automatically invoked and will delete Carlos's file.


# 5. Exploiting Java deserialization with Apache Commons
This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains.

To solve the lab, use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in to your own account and observe that the session cookie contains a serialized Java object. Send a request containing your session cookie to Burp Repeater.
2. Download the "ysoserial"(https://github.com/frohoff/ysoserial) tool and execute the following command. This generates a Base64-encoded serialized object containing your payload:
    - In Java versions 16 and above:
        ```powershell
        java -jar ysoserial-all.jar \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \ --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \ --add-opens=java.base/java.net=ALL-UNNAMED \ --add-opens=java.base/java.util=ALL-UNNAMED \ CommonsCollections4 'rm /home/carlos/morale.txt' | base64
        ```
    - In Java versions 15 and below:
        ```powershell
     java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
        ```
3. In Burp Repeater, replace your session cookie with the malicious one you just created. Select the entire cookie and then URL-encode it. Send the request to solve the lab.

**Workflow**:
1. Log in to your own account and observe that the session cookie contains a serialized Java object. Send a request containing your session cookie to Burp Repeater.
	![](Pasted%20image%2020250326053403.png)
	![](Pasted%20image%2020250326053423.png)
2.  Download the "ysoserial"(https://github.com/frohoff/ysoserial) tool and execute the following command. This generates a Base64-encoded serialized object containing your payload:
```powershell
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```
![](Pasted%20image%2020250326053704.png)
	![](Pasted%20image%2020250326053735.png)
3.  In Burp Repeater, replace your session cookie with the malicious one you just created. **Select the entire cookie and then URL-encode it**. Send the request to solve the lab.
	![](Pasted%20image%2020250326054049.png)


# 6. Exploiting PHP deserialization with a pre-built gadget chain
This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's insecure deserialization using pre-built gadget chains.

To solve the lab, identify the target framework then use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, work out how to generate a valid signed cookie containing your malicious object. Finally, pass this into the website to delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in and send a request containing your session cookie to Burp Repeater. Highlight the cookie and look at the **Inspector** panel. Notice that the cookie contains a Base64-encoded token, signed with a SHA-1 HMAC hash.
2. Copy the decoded cookie from the **Inspector** and paste it into Decoder. In Decoder, highlight the token and then select **Decode as > Base64**. Notice that the token is actually a serialized PHP object.
3. In Burp Repeater, observe that if you try sending a request with a modified cookie, an exception is raised because the digital signature no longer matches. However, you should notice that:
    - A developer comment discloses the location of a debug file at `/cgi-bin/phpinfo.php`.
    - The error message reveals that the website is using the Symfony 4.3.6 framework.
4. Request the `/cgi-bin/phpinfo.php` file in Burp Repeater and observe that it leaks some key information about the website, including the `SECRET_KEY` environment variable. Save this key; you'll need it to sign your exploit later.
5. Download the "PHPGGC" tool and execute the following command:
    `./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64`
    
    **This will generate a Base64-encoded serialized object that exploits an RCE gadget chain in Symfony to delete Carlos's `morale.txt` file.**
6. You now need to construct a valid cookie containing this malicious object and sign it correctly using the secret key you obtained earlier. You can use the following PHP script to do this. Before running the script, you just need to make the following changes:
    - Assign the object you generated in PHPGGC to the `$object` variable.
    - Assign the secret key that you copied from the `phpinfo.php` file to the `$secretKey` variable.
    ```php
    <?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```
7. In Burp Repeater, replace your session cookie with the malicious one you just created, then send the request to solve the lab.

**Workflow:**
1. Log in and send a request containing your session cookie to Burp Repeater. Highlight the cookie and look at the **Inspector** panel. Notice that the cookie contains a Base64-encoded token, signed with a SHA-1 HMAC hash.   ![](Pasted%20image%2020250328010213.png)
2. Copy the decoded cookie from the **Inspector** and paste it into Decoder. In Decoder, highlight the token and then select **Decode as > Base64**. Notice that the token is actually a serialized PHP object.
	![](Pasted%20image%2020250328010350.png)
3. In Burp Repeater, observe that if you try sending a request with a modified cookie, an exception is raised because the digital signature no longer matches. However, you should notice that:
    - A developer comment discloses the location of a debug file at `/cgi-bin/phpinfo.php`.
    - The error message reveals that the website is using the Symfony 4.3.6 framework.
    ![](Pasted%20image%2020250328010815.png)
	![](Pasted%20image%2020250328010546.png)
4. Request the `/cgi-bin/phpinfo.php` file in Burp Repeater and observe that it leaks some key information about the website, including the `SECRET_KEY` environment variable
	![](Pasted%20image%2020250328011051.png)
5. Using 'PHPGGC' tool generate a Base64-encoded serialized object that exploits an RCE gadget chain in Symfony to delete Carlos's `morale.txt` file.
	`./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64`

    ![](Pasted%20image%2020250328011441.png)
    ![](Pasted%20image%2020250328011524.png)
    ![](Pasted%20image%2020250328011624.png)

7. Construct a valid cookie containing this malicious object and sign it correctly using the secret key you obtained earlier. You can use the following PHP script to do this. Before running the script, you just need to make the following changes:
    - Assign the object you generated in PHPGGC to the `$object` variable.
    - Assign the secret key that you copied from the `phpinfo.php` file to the `$secretKey` variable.
```php 
<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```
![](Pasted%20image%2020250328012049.png)
8. In Burp Repeater, replace your session cookie with the malicious one you just created, then send the request to solve the lab.
	![](Pasted%20image%2020250328012113.png)


# 7. Exploiting Ruby deserialization using a documented gadget chain
This lab uses a serialization-based session mechanism and the Ruby on Rails framework. There are documented exploits that enable remote code execution via a gadget chain in this framework.

To solve the lab, find a documented exploit and adapt it to create a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener: peter`

**Analysis:**
1. Log in to your own account and notice that the session cookie contains a serialized ("marshaled") Ruby object. Send a request containing this session cookie to Burp Repeater.
2. Browse the web to find the `Universal Deserialisation Gadget for Ruby 2.x-3.x` by `vakzz` on `devcraft.io`. Copy the final script for generating the payload.
3. Modify the script as follows:
    - Change the command that should be executed from `id` to `rm /home/carlos/morale.txt`.
    - Replace the final two lines with `puts Base64.encode64(payload)`. This ensures that the payload is output in the correct format for you to use for the lab.
4. Run the script and copy the resulting Base64-encoded object. In Burp Repeater, replace your session cookie with the malicious one that you just created, then URL encode it.

**Workflow**:
1. Log in to your own account and notice that the session cookie contains a serialized ("marshaled") Ruby object. Send a request containing this session cookie to Burp Repeater.
	![](Pasted%20image%2020250328032353.png)
	![](Pasted%20image%2020250328032428.png)
2.  Browse the web to find the `Universal Deserialisation Gadget for Ruby 2.x-3.x` by `vakzz` on `devcraft.io`. Copy the final script for generating the payload.
	https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
	![](Pasted%20image%2020250328032724.png)

3. Modify the script as follows and compile it using an online ruby compiler:
    - Change the command that should be executed from `id` to `rm /home/carlos/morale.txt`.
    - Replace the final two lines with `puts Base64.encode64(payload)`. This ensures that the payload is output in the correct format for you to use for the lab.
	![](Pasted%20image%2020250328033057.png)
4. Run the script and copy the resulting Base64-encoded object. In Burp Repeater, replace your session cookie with the malicious one that you just created, **then URL encode it.**
	![](Pasted%20image%2020250328033239.png)
	![](Pasted%20image%2020250328033302.png)


# 8. Developing a custom gadget chain for PHP deserialization (expert)

This lab uses a serialization-based session mechanism. By deploying a custom gadget chain, you can exploit its insecure deserialization to achieve remote code execution. To solve the lab, delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in to your own account and notice that the session cookie contains a serialized PHP object. Notice that the website references the file `/cgi-bin/libs/CustomTemplate.php`. Obtain the source code by submitting a request using the `.php~` backup file extension.
2. In the source code, notice that the `__wakeup()` magic method for a `CustomTemplate` will create a new `Product` by referencing the `default_desc_type` and `desc` from the `CustomTemplate`.
3. Also notice that the `DefaultMap` class has the `__get()` magic method, which will be invoked if you try to read an attribute that doesn't exist for this object. This magic method invokes `call_user_func()`, which will execute any function that is passed into it via the `DefaultMap->callback` attribute. The function will be executed on the `$name`, which is the non-existent attribute that was requested.
4. You can exploit this gadget chain to invoke `exec(rm /home/carlos/morale.txt)` by passing in a `CustomTemplate` object where:

    `CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt"; CustomTemplate->desc = DefaultMap; DefaultMap->callback = "exec"`
    If you follow the data flow in the source code, you will notice that this causes the `Product` constructor to try and fetch the `default_desc_type` from the `DefaultMap` object. As it doesn't have this attribute, the `__get()` method will invoke the callback `exec()` method on the `default_desc_type`, which is set to our shell command.
    
5. To solve the lab, Base64 and URL-encode the following serialized object, and pass it into the website via your session cookie:

**Workflow**:
1. Log in to your own account and notice that the session cookie contains a serialized PHP object. Notice that the website references the file `/cgi-bin/libs/CustomTemplate.php`. Obtain the source code by submitting a request using the `.php~` backup file extension.
	![](Pasted%20image%2020250328051555%201.png)
	![](Pasted%20image%2020250328051732%201.png)
2. In the source code, notice that the `__wakeup()` magic method for a `CustomTemplate` will create a new `Product` by referencing the `default_desc_type` and `desc` from the `CustomTemplate`.
	![](Pasted%20image%2020250328052046%201.png)
3. Also notice that the `DefaultMap` class has the `__get()` magic method, which will be invoked if you try to read an attribute that doesn't exist for this object. This magic method invokes `call_user_func()`, which will execute any function that is passed into it via the `DefaultMap->callback` attribute. The function will be executed on the `$name`, which is the non-existent attribute that was requested.
	![](Pasted%20image%2020250328052759%201.png)
4. You can exploit this gadget chain to invoke `exec(rm /home/carlos/morale.txt)` by passing in a `CustomTemplate` object where:
    `CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt"; CustomTemplate->desc = DefaultMap; DefaultMap->callback = "exec"`
    
    If you follow the data flow in the source code, you will notice that this causes the `Product` constructor to try and fetch the `default_desc_type` from the `DefaultMap` object. As it doesn't have this attribute, the `__get()` method will invoke the callback `exec()` method on the `default_desc_type`, which is set to our shell command.
	![](Pasted%20image%2020250328053159%201.png)
	Base64 and URL-encode the following serialized object, and pass it into the website via your session cookie.

-----------------------------------------------------------------------
**Gadget chain exploitation detailed:**
Looking at the source code revealed we can see several important components:
- **Custom Template Class**: Contains a constructor and magic method `__wakeup()` that builds a product
- **Product Class**: Takes parameters from the CustomTemplate to build itself
- **Description Class**: Defines HTML and text descriptions
- **Default Map Class**: Contains a dangerous `__get()` method that executes callbacks

PHP has special functions called "magic methods" that automatically run during certain events:
- `__construct()`: Runs when an object is created
- `__wakeup()`: Runs when an object is deserialized
- `__get()`: Runs when you try to access a property that doesn't exist
- `__destruct()`: Runs when an object is destroyed

`O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}`

This serialized object represents:
- A CustomTemplate object with 2 properties
- `default_desc_type` containing our shell command (rm /home/carlos...)
- `desc` containing a DefaultMap object with its callback set to `exec`

The vulnerability exists because of a "gadget chain" where multiple classes interact in a way that allows code execution:
- When PHP deserializes the session cookie, it creates objects and calls magic methods
- The `__wakeup()` method in CustomTemplate calls `build_product()`. This creates a new Product using `$this->default_desc_type` and `$this->desc`
- If we can control these values, we can create a chain where:
    - `default_desc_type` is our shell command (`rm /home/carlos/morale.txt`)
    - `desc` is a DefaultMap object and DefaultMap's callback is set to `exec`

1. **First Gadget - CustomTemplate**:
- When deserialized, its `__wakeup()` method runs. This method calls `build_product()` which creates a new Product with the values of `default_desc_type` and `desc`.

2. **Second Gadget - Product Constructor**:
- Product constructor tries to use `desc->default_desc_type`; but `desc` is a DefaultMap object, not a string and doesn't have a `default_desc_type` property

3. **Third Gadget - DefaultMap's __get Method**:
- When it tries to access the non-existent `default_desc_type`, PHP calls DefaultMap's `__get("default_desc_type")` method (because does not not exist) which contains: `return call_user_func($this->callback, $name);`
- This translates to: `call_user_func("exec", "rm /home/carlos/morale.txt");` which simply executes: `exec("rm /home/carlos/morale.txt");`

![](Pasted%20image%2020250329143107.png)

s:17:"default_desc_type" --> s:26:"rm /home/carlos/morale.txt" 
	**'default_desc_type' = 'rm /home/carlos/morale.txt'** 
	
s:4:"desc"; --> O:10:"DefaultMap" ({ s:8:"callback" --> s:4:"exec"; }
	**'desc' = 'DefaultMap'** object WHERE **'callback' = 'exec'**

desc(default_desc_type) ==> DefaultMap(default_desc_type) == _ _get(default_desc_type)  ==> return(callback, default_desc_type) ==> return(exec, 'rm /home/carlos/morale.txt) ==> exec(rm /home/carlos/morale.txt)


-----------------------------------------------------------------------
# 9. Using PHAR deserialization to deploy a custom gadget chain (expert)
This lab does not explicitly use deserialization. However, if you combine `PHAR` deserialization with other advanced hacking techniques, you can still achieve remote code execution via a custom gadget chain.

To solve the lab, delete the `morale.txt` file from Carlos's home directory. You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Observe that the website has a feature for uploading your own avatar, which only accepts `JPG` images. Upload a valid `JPG` as your avatar. Notice that it is loaded using `GET /cgi-bin/avatar.php?avatar=wiener`.
2. In Burp Repeater, request `GET /cgi-bin` to find an index that shows a `Blog.php` and `CustomTemplate.php` file. Obtain the source code by requesting the files using the `.php~` backup extension.
3. Study the source code and identify the gadget chain involving the `Blog->desc` and `CustomTemplate->lockFilePath` attributes. Notice that the `file_exists()` filesystem method is called on the `lockFilePath` attribute.
4. Notice that the website uses the Twig template engine. You can use deserialization to pass in an server-side template injection (SSTI) payload. Find a documented SSTI payload for remote code execution on Twig, and adapt it to delete Carlos's file:
    ```TWIG
    {{_self.env.registerUndefinedFilterCallback("exec")}}  {{_self.env.getFilter("rm /home/carlos/morale.txt")}}
    ```
5. Write a some PHP for creating a `CustomTemplate` and `Blog` containing your SSTI payload:
    ```PHP
    class CustomTemplate {} 
    class Blog {} 
    $object = new CustomTemplate; 
    $blog = new Blog; 
    $blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}'; 
    $blog->user = 'user'; 
    $object->template_file_path = $blog;
    ```
6. Create a `PHAR-JPG` polyglot containing your PHP script. You can find several scripts for doing this online (search for "`phar jpg polyglot`"). Alternatively, you can download our [ready-made one](https://github.com/PortSwigger/serialization-examples/blob/master/php/phar-jpg-polyglot.jpg).
7. Upload this file as your avatar. In Burp Repeater, modify the request line to deserialize your malicious avatar using a `phar://` stream as follows:  `GET /cgi-bin/avatar.php?avatar=phar://wiener`

-----------------------------------------------------------------------
PHP provides several URL-style wrappers that you can use for handling different protocols when accessing file paths. One of these is the `phar://` wrapper, which provides a stream interface for accessing PHP Archive (`.phar`) files.

The PHP documentation reveals that `PHAR` manifest files contain serialized metadata. Crucially, if you perform any filesystem operations on a `phar://` stream, this metadata is implicitly deserialized. This means that a `phar://` stream can potentially be a vector for exploiting insecure deserialization, provided that you can pass this stream into a filesystem method.

In the case of obviously dangerous filesystem methods, such as `include()` or `fopen()`, websites are likely to have implemented counter-measures to reduce the potential for them to be used maliciously. However, methods such as `file_exists()`, which are not so overtly dangerous, may not be as well protected.

This technique also requires you to upload the `PHAR` to the server somehow. One approach is to use an image upload functionality, for example. If you are able to create a polyglot file, with a `PHAR` masquerading as a simple `JPG`, you can sometimes bypass the website's validation checks. If you can then force the website to load this polyglot "`JPG`" from a `phar://` stream, any harmful data you inject via the `PHAR` metadata will be deserialized. As the file extension is not checked when PHP reads a stream, it does not matter that the file uses an image extension.

As long as the class of the object is supported by the website, both the `__wakeup()` and `__destruct()` magic methods can be invoked in this way, allowing you to potentially kick off a gadget chain using this technique.


**Workflow**:
1. Observe that the website has a feature for uploading your own avatar, which only accepts `JPG` images. Upload a valid `JPG` as your avatar. Notice that it is loaded using `GET /cgi-bin/avatar.php?avatar=wiener`.
	tried to upload a .png file and it is not accepted
	![](Pasted%20image%2020250329151403.png)
	browsing trough the web application posts I observed that .jpg extension is allowed
	![](Pasted%20image%2020250329152409.png)
	![](Pasted%20image%2020250329152733.png)
	After upload a valid .jpg image i have noticed that it is loaded using `GET /cgi-bin/avatar.php?avatar=wiener`.
	![](Pasted%20image%2020250329153454.png)
2. In Burp Repeater, request `GET /cgi-bin` to find an index that shows a `Blog.php` and `CustomTemplate.php` file. Obtain the source code by requesting the files using the `.php~` backup extension. 
	![](Pasted%20image%2020250329153714.png)
3. Study the source code and identify the gadget chain involving the `Blog->desc` and `CustomTemplate->lockFilePath` attributes. Notice that the `file_exists()` filesystem method is called on the `lockFilePath` attribute.
	`CustomTemplate.php` file:
	![](Pasted%20image%2020250329153901.png)
	`Blog.php` file:
	![](Pasted%20image%2020250329154030.png)
4. The website uses the Twig template engine. You can use deserialization to pass in an server-side template injection (SSTI) payload. Find a documented SSTI payload for remote code execution on Twig, and adapt it to delete Carlos's file. Write a some PHP for creating a `CustomTemplate` and `Blog` containing your SSTI payload:
    ```PHP
    class CustomTemplate {} 
    class Blog {} 
    $object = new CustomTemplate; 
    $blog = new Blog; 
    $blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}'; 
    $blog->user = 'user'; 
    $object->template_file_path = $blog;
```
	![](Pasted%20image%2020250329160215.png)
5. Create a `PHAR-JPG` polyglot containing your PHP script. You can find several scripts for doing this online (search for "`phar jpg polyglot`"). 
	We will use this repo:
	https://github.com/kunte0/phar-jpg-polyglot
	![](Pasted%20image%2020250329160356.png)
	we have to edit the second php file from repo which is **phar_japg_polyglot.php** which our own php class exploit described above
	![](Pasted%20image%2020250329160539.png)
	![](Pasted%20image%2020250329160650.png)
		![](Pasted%20image%2020250329160737.png)
	we will run the full repo comand (**php.ini** + **phar_japg_polyglot.php**) to generate our polyglot jpg file with SSTI serialized exploit
	![](Pasted%20image%2020250329160957.png)
6. Upload this file as your avatar. In Burp Repeater, modify the request line to deserialize your malicious avatar using a `phar://` stream as follows:  `GET /cgi-bin/avatar.php?avatar=phar://wiener`
	![](Pasted%20image%2020250329161031.png)
	![](Pasted%20image%2020250329161220.png)


-----------------------------------------------------------------------
# 10. Developing a custom gadget chain for Java deserialization (expert)
This lab uses a serialization-based session mechanism. If you can construct a suitable gadget chain, you can exploit this lab's insecure deserialization to obtain the administrator's password.

To solve the lab, gain access to the source code and use it to construct a gadget chain to obtain the administrator's password. Then, log in as the `administrator` and delete `carlos`You can log in to your own account using the following credentials: `wiener:peter`

ref: https://www.youtube.com/watch?v=O5FooPYSz1E&t=129s