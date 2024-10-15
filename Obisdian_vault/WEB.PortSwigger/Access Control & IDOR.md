https://portswigger.net/web-security/access-control
# **1. Unprotected admin functionality**
This lab has an unprotected admin panel. Solve the lab by deleting the user `carlos`.

1. Go to the lab and view `robots.txt` by appending `/robots.txt` to the lab URL. Notice that the `Disallow` line discloses the path to the admin panel.
2. In the URL bar, replace `/robots.txt` with `/administrator-panel` to load the admin panel.
3. Delete `carlos`.

Analysis:
![[Pasted image 20241014020115.png]]

# **2. Unprotected admin functionality with unpredictable URL**
This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.
Solve the lab by accessing the admin panel, and using it to delete the user `carlos`.

1. Review the lab home page's source using Burp Suite or your web browser's developer tools.
2. Observe that it contains some JavaScript that discloses the URL of the admin panel.
3. Load the admin panel and delete `carlos`.

Analysis:
![[Pasted image 20241014022505.png]]
	![[Pasted image 20241014022559.png]]

# **3. User role controlled by request parameter**
This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.
Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

1. Browse to `/admin` and observe that you can't access the admin panel.
2. Browse to the login page.
3. In Burp Proxy, turn interception on and enable response interception.
4. Complete and submit the login page, and forward the resulting request in Burp.
5. Observe that the response sets the cookie `Admin=false`. Change it to `Admin=true`.
6. Load the admin panel and delete `carlos`.

Analysis:
![[Pasted image 20241014031954.png]]
	![[Pasted image 20241014032045.png]]

- inspect page and modify admin cookie accordingly to have acces to the admin pannel
	 ![[Pasted image 20241014032503.png]]

# **4. User role can be modified in user profile**
This lab has an admin panel at `/admin`. It's only accessible to logged-in users with a `roleid` of 2.
Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

1. Log in using the supplied credentials and access your account page.
2. Use the provided feature to update the email address associated with your account.
3. Observe that the response contains your role ID.
4. Send the email submission request to Burp Repeater, add `"roleid":2` into the JSON in the request body, and resend it.
5. Observe that the response shows your `roleid` has changed to 2.
6. Browse to `/admin` and delete `carlos`.

Analysis:
![[Pasted image 20241014040544.png]]

![[Pasted image 20241014040928.png]]

# **5. User ID controlled by request parameter**
This lab has a horizontal privilege escalation vulnerability on the user account page.
To solve the lab, obtain the API key for the user carlos and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

1. Log in using the supplied credentials and go to your account page.
2. Note that the URL contains your username in the "id" parameter.
3. Send the request to Burp Repeater.
4. Change the "id" parameter to `carlos`.
5. Retrieve and submit the API key for `carlos`.

Analysis:
![[Pasted image 20241015161029.png]]
![[Pasted image 20241015161138.png]]

# **6.  User ID controlled by request parameter, with unpredictable user IDs**
This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs. To solve the lab, find the GUID for `carlos`, then submit his API key as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

1. Find a blog post by `carlos`.
2. Click on `carlos` and observe that the URL contains his user ID. Make a note of this ID.
3. Log in using the supplied credentials and access your account page.
4. Change the "id" parameter to the saved user ID.
5. Retrieve and submit the API key.

Analysis:
-  Log into the Wiener account
-  Loop trough all the posts and identify which one is written by the user Carlos
-  Extract the GUID
-  Access the Carlos account replacing the GUID in the my account request
-  Extract the API key of Carlos

![[Pasted image 20241015155547.png]]
![[Pasted image 20241015155826.png]]

- extracting&replacing GUID in my account page/request
![[Pasted image 20241015160137.png]]

# **7.  User ID controlled by request parameter with data leakage in redirect**
This lab contains an [access control](https://portswigger.net/web-security/access-control) vulnerability where sensitive information is leaked in the body of a redirect response. To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

1. Log in using the supplied credentials and access your account page.
2. Send the request to Burp Repeater.
3. Change the "id" parameter to `carlos`.
4. Observe that although the response is now redirecting you to the home page, it has a body containing the API key belonging to `carlos`.
5. Submit the API key.

Analysis:

- log into wiener account
- change URL user id with carlos and notice the redirect leaking
- extract carlos API key 
![[Pasted image 20241015172329.png]]

# **8. User ID controlled by request parameter with password disclosure**
This lab has user account page that contains the current user's existing password, prefilled in a masked input. To solve the lab, retrieve the administrator's password, then use it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

1. Log in using the supplied credentials and access the user account page.
2. Change the "id" parameter in the URL to `administrator`.
3. View the response in Burp and observe that it contains the administrator's password.
4. Log in to the administrator account and delete `carlos`.

Analysis:
![[Pasted image 20241015172858.png]]

# **9. Insecure direct object references**
This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

Solve the lab by finding the password for the user `carlos`, and logging into their account.

1. Select the **Live chat** tab.
2. Send a message and then select **View transcript**.
3. Review the URL and observe that the transcripts are text files assigned a filename containing an incrementing number.
4. Change the filename to `1.txt` and review the text. Notice a password within the chat transcript.
5. Return to the main lab page and log in using the stolen credentials.

Analysis:
![[Pasted image 20241015173811.png]]

# **10.  URL-based access control can be circumvented**