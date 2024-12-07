Password reset mechanism is an important part of user convenience in modern web applications. However, their implementation requires careful security considerations because poorly secured password reset processes can be easily exploited.

**Email-Based Reset**
When a user resets their password, the application sends an email containing a reset link or a token to the user’s registered email address. The user then clicks on this link, which directs them to a page where they can enter a new password and confirm it, or a system will automatically generate a new password for the user. This method relies heavily on the security of the user's email account and the secrecy of the link or token sent.

**Security Question-Based Reset**
This involves the user answering a series of pre-configured security questions they had set up when creating their account. If the answers are correct, the system allows the user to proceed with resetting their password. While this method adds a layer of security by requiring information only the user should know, it can be compromised if an attacker gains access to personally identifiable information (PII), which can sometimes be easily found or guessed.

**SMS-Based Reset**
This functions similarly to email-based reset but uses SMS to deliver a reset code or link directly to the user’s mobile phone. Once the user receives the code, they can enter it on the provided webpage to access the password reset functionality. This method assumes that access to the user's phone is secure, but it can be vulnerable to SIM swapping attacks or intercepts.

## Vulnerabilities:
- **Predictable Tokens**: If the reset tokens used in links or SMS messages are predictable or follow a sequential pattern, attackers might guess or brute-force their way to generate valid reset URLs.
- **Token Expiration Issues**: Tokens that remain valid for too long or do not expire immediately after use provide a window of opportunity for attackers. It’s crucial that tokens expire swiftly to limit this window.
- **Insufficient Validation**: The mechanisms for verifying a user’s identity, like security questions or email-based authentication, might be weak and susceptible to exploitation if the questions are too common or the email account is compromised.
- **Information Disclosure**: Any error message that specifies whether an email address or username is registered can inadvertently help attackers in their enumeration efforts, confirming the existence of accounts.
- **Insecure Transport**: The transmission of reset links or tokens over non-HTTPS connections can expose these critical elements to interception by network eavesdroppers.

## Exploiting Predictable Tokens
Tokens that are simple, predictable, or have long expiration times can be particularly vulnerable to interception or brute force. For example, the below code is used by the vulnerable application hosted in the Predictable Tokens lab:
```php
$token = mt_rand(100, 200);
$query = $conn->prepare("UPDATE users SET reset_token = ? WHERE email = ?");
$query->bind_param("ss", $token, $email);
$query->execute();
```

The code above sets a random three-digit PIN as the reset token of the submitted email. Since this token doesn't employ mixed characters, it can be easily brute-forced.

 Code breakdown
    - `mt_rand(100, 200)` generates a random integer between 100 and 200 using the Mersenne Twister random number generator.
    - This value is assigned to the variable `$token`.
    - `$conn->prepare(...)` prepares an SQL query to update the `reset_token` field in the `users` table for the user with the specified `email`.
    - The `?` placeholders are used to avoid SQL injection by binding parameters securely.
    - `bind_param("ss", $token, $email)` binds the variables `$token` and `$email` to the `?` placeholders in the query.
        - `"ss"` specifies the types of the parameters:
            - `s` means a string type.
            - In this case, `$token` is treated as a string despite being an integer, as MySQL accepts values in string format.
            - `$email` is a string representing the email of the user.
    - This executes the prepared SQL query with the bound parameters.
    - The `reset_token` field in the database will be updated with the value of `$token` for the user whose email matches `$email`.

## Example
Navigate to the application's password reset page, input "admin@admin.com" in the Email input field, and click Submit.
	![](Pasted%20image%2020241126234934.png)![](Pasted%20image%2020241126234943.png)
For demonstration purposes, the web application uses the reset link: `http://enum.thm/labs/predictable_tokens/reset_password.php?token=123`
	![](Pasted%20image%2020241126235003.png)
Notice the token is a simple numeric value. Using Burp Suite, navigate to the above URL and capture the request. Subsequently, send the request to the Intruder, highlight the value of the token parameter, and click the Add payload button, as shown below.
	![](Pasted%20image%2020241126235026.png)
Using the AttackBox or your own attacking VM, use Crunch to generate a list of numbers from 100 to 200. This list will be used as the dictionary in the brute-force attack.
```shell-session
user@tryhackme $ crunch 3 3 -o otp.txt -t %%% -s 100 -e 200             

Crunch will now generate the following amount of data: 404 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 101 

crunch: 100% completed generating output
```

Go back to Intruder and configure the payload to use the generated file.
	![](Pasted%20image%2020241126235142.png)![](Pasted%20image%2020241126235146.png)
 Once successful, you will get a response with a much bigger content length compared to the responses with an "Invalid token" error message.
	 ![](Pasted%20image%2020241126235215.png)
	 