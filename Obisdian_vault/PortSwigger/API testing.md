https://portswigger.net/web-security/api-testing

# **1.Exploiting an API endpoint using documentation**
To solve the lab, find the exposed API documentation and delete `carlos`. You can log in to your own account using the following credentials: `wiener:peter`.

1. In Burp's browser, log in to the application using the credentials `wiener:peter` and update your email address.
2. In **Proxy > HTTP history**, right-click the `PATCH /api/user/wiener` request and select **Send to Repeater**.
3. Go to the **Repeater** tab. Send the `PATCH /api/user/wiener` request. Notice that this retrieves credentials for the user `wiener`.
4. Remove `/wiener` from the path of the request, so the endpoint is now `/api/user`, then send the request. Notice that this returns an error because there is no user identifier.
5. Remove `/user` from the path of the request, so the endpoint is now `/api`, then send the request. Notice that this retrieves API documentation.
6. Right-click the response and select **Show response in browser**. Copy the URL.
7. Paste the URL into Burp's browser to access the documentation. Notice that the documentation is interactive.
8. To delete Carlos and solve the lab, click on the `DELETE` row, enter `carlos`, then click **Send request**.

Analysis:

![[Pasted image 20241025042718.png]]
![[Pasted image 20241025042435.png]]
![[Pasted image 20241025043216.png]]

# 2.Exploiting server-side parameter pollution in a query string

To solve the lab, log in as the `administrator` and delete `carlos`.

1. In Burp's browser, trigger a password reset for the `administrator` user.
2. In **Proxy > HTTP history**, notice the `POST /forgot-password` request and the related `/static/js/forgotPassword.js` JavaScript file.
3. Right-click the `POST /forgot-password` request and select **Send to Repeater**.
4. In the **Repeater** tab, resend the request to confirm that the response is consistent.
5. Change the value of the `username` parameter from `administrator` to an invalid username, such as `administratorx`. Send the request. Notice that this results in an `Invalid username` error message.
6. Attempt to add a second parameter-value pair to the server-side request using a URL-encoded `&` character. For example, add URL-encoded `&x=y`:
    `username=administrator%26x=y`
    Send the request. Notice that this returns a `Parameter is not supported` error message. This suggests that the internal API may have interpreted `&x=y` as a separate parameter, instead of part of the username.
7. Attempt to truncate the server-side query string using a URL-encoded `#` character:
    `username=administrator%23`
    Send the request. Notice that this returns a `Field not specified` error message. This suggests that the server-side query may include an additional parameter called `field`, which has been removed by the `#` character.
8. Add a `field` parameter with an invalid value to the request. Truncate the query string after the added parameter-value pair. For example, add URL-encoded `&field=x#`:
    `username=administrator%26field=x%23`
    Send the request. Notice that this results in an `Invalid field` error message. This suggests that the server-side application may recognize the injected field parameter.
9. Brute-force the value of the `field` parameter:
    1. Right-click the `POST /forgot-password` request and select **Send to Intruder**.
    2. In the **Intruder** tab, add a payload position to the value of the `field` parameter as follows:
        `username=administrator%26field=§x§%23`
    3. In the **Payloads** side panel, under **Payload configuration**, click **Add from list**. Select the built-in **Server-side variable names** payload list, then start the attack.
    4. Review the results. Notice that the requests with the username and email payloads both return a `200` response.
10. Change the value of the `field` parameter from `x#` to `email`:
    `username=administrator%26field=email%23`
    Send the request. Notice that this returns the original response. This suggests that `email` is a valid field type.
11. In **Proxy > HTTP history**, review the `/static/js/forgotPassword.js` JavaScript file. Notice the password reset endpoint, which refers to the `reset_token` parameter:
    `/forgot-password?reset_token=${resetToken}`
12. In the **Repeater** tab, change the value of the `field` parameter from `email` to `reset_token`:
    `username=administrator%26field=reset_token%23`
    Send the request. Notice that this returns a password reset token. Make a note of this.
13. In Burp's browser, enter the password reset endpoint in the address bar. Add your password reset token as the value of the `reset_token` parameter . For example:
    `/forgot-password?reset_token=123456789`
14. Set a new password.
15. Log in as the `administrator` user using your password.
16. Go to the **Admin panel** and delete `carlos` to solve the lab.

Analysis:
