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

# **2.Exploiting server-side parameter pollution in a query string**
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

The **truncation test** (with `#`) accidentally revealed that the server expects a `field` parameter, even though we hadn’t specified it explicitly.

- The server was fine with just `username=administrator` until we started experimenting with SSPP.
- Using `%26` (addition) to see if the server could handle extra parameters  
- Using `%23` (truncation) led to the discovery that `field` was required, suggesting internal logic that expected a `field` parameter in the request structure.
- Brute forcing `field` parameter  // using `reset_token` as a `field` value for disclosure 

This discovery was not because SSPP altered the server’s logic but rather because truncation revealed an existing dependency on the `field` parameter, likely tied to how the server internally parses and processes the query string for `/forgot-password`.

![[Pasted image 20241026031431.png]]

![[Pasted image 20241026031530.png]]

![[Pasted image 20241026031802.png]]

![[Pasted image 20241026031950.png]]
![[Pasted image 20241026032122.png]]
![[Pasted image 20241026032408.png]]
![[Pasted image 20241026032559.png]]
![[Pasted image 20241026033037.png]]

# **3.Finding and exploiting an unused API endpoint**
To solve the lab, exploit a hidden API endpoint to buy a **Lightweight l33t Leather Jacket**. You can log in to your own account using the following credentials: `wiener:peter`.

1. In Burp's browser, access the lab and click on a product.
2. In **Proxy > HTTP history**, notice the API request for the product. For example, `/api/products/3/price`.
3. Right-click the API request and select **Send to Repeater**.
4. In the **Repeater** tab, change the HTTP method for the API request from `GET` to `OPTIONS`, then send the request. Notice that the response specifies that the `GET` and `PATCH` methods are allowed.
5. Change the method for the API request from `GET` to `PATCH`, then send the request. Notice that you receive an `Unauthorized` message. This may indicate that you need to be authenticated to update the order.
6. In Burp's browser, log in to the application using the credentials `wiener:peter`.
7. Click on the **Lightweight "l33t" Leather Jacket** product.
8. In **Proxy > HTTP history**, right-click the `API/products/1/price` request for the leather jacket and select **Send to Repeater**.
9. In the **Repeater** tab, change the method for the API request from `GET` to `PATCH`, then send the request. Notice that this causes an error due to an incorrect `Content-Type`. The error message specifies that the `Content-Type` should be `application/json`.
10. Add a `Content-Type` header and set the value to `application/json`.
11. Add an empty JSON object `{}` as the request body, then send the request. Notice that this causes an error due to the request body missing a `price` parameter.
12. Add a `price` parameter with a value of `0` to the JSON object `{"price":0}`. Send the request.
13. In Burp's browser, reload the leather jacket product page. Notice that the price of the leather jacket is now `$0.00`.
![[Pasted image 20241026234635.png]]
![[Pasted image 20241026234717.png]]
![[Pasted image 20241026235011.png]]
![[Pasted image 20241026235208.png]]
- add to cart now :)

# **4.Exploiting a mass assignment vulnerability**
To solve the lab, find and exploit a mass assignment vulnerability to buy a **Lightweight l33t Leather Jacket**. You can log in to your own account using the following credentials: `wiener:peter`.

1. In Burp's browser, log in to the application using the credentials `wiener:peter`.
2. Click on the **Lightweight "l33t" Leather Jacket** product and add it to your basket.
3. Go to your basket and click **Place order**. Notice that you don't have enough credit for the purchase.
4. In **Proxy > HTTP history**, notice both the `GET` and `POST` API requests for `/api/checkout`.
5. Notice that the response to the `GET` request contains the same JSON structure as the `POST` request. Observe that the JSON structure in the `GET` response includes a `chosen_discount` parameter, which is not present in the `POST` request.
6. Right-click the `POST /api/checkout` request and select **Send to Repeater**.
7. In Repeater, add the `chosen_discount` parameter to the request. The JSON should look like the following:
```
{
    "chosen_discount":{
        "percentage":0
    },
    "chosen_products":[
        {
            "product_id":"1",
            "quantity":1
        }
    ]
}
```
8. Send the request. Notice that adding the `chosen_discount` parameter doesn't cause an error.
9. Change the `chosen_discount` value to the string `"x"`, then send the request. Observe that this results in an error message as the parameter value isn't a number. This may indicate that the user input is being processed.
10. Change the `chosen_discount` percentage to `100`, then send the request to solve the lab.

Analysis:
![[Pasted image 20241027000011.png]]
![[Pasted image 20241027000027.png]]
![[Pasted image 20241027000325.png]]

# **5.Exploiting server-side parameter pollution in a REST URL**
To solve the lab, log in as the `administrator` and delete `carlos`.

1. In Burp's browser, trigger a password reset for the `administrator` user.
2. In **Proxy > HTTP history**, notice the `POST /forgot-password` request and the related `/static/js/forgotPassword.js` JavaScript file.
3. Right-click the `POST /forgot-password` request and select **Send to Repeater**.
4. In the **Repeater** tab, resend the request to confirm that the response is consistent.
5. Send a variety of requests with a modified username parameter value to determine whether the input is placed in the URL path of a server-side request without escaping:
    1. Submit URL-encoded `administrator#` as the value of the `username` parameter.
        Notice that this returns an `Invalid route` error message. This suggests that the server may have placed the input in the path of a server-side request, and that the fragment has truncated some trailing data. Observe that the message also refers to an API definition.
    2. Change the value of the username parameter from `administrator%23` to URL-encoded `administrator?`, then send the request.
        Notice that this also returns an `Invalid route` error message. This suggests that the input may be placed in a URL path, as the `?` character indicates the start of the query string and therefore truncates the URL path.
    3. Change the value of the `username` parameter from `administrator%3F` to `./administrator` then send the request.
        Notice that this returns the original response. This suggests that the request may have accessed the same URL path as the original request. This further indicates that the input may be placed in the URL path.
    4. Change the value of the username parameter from `./administrator` to `../administrator`, then send the request.

        Notice that this returns an `Invalid route` error message. This suggests that the request may have accessed an invalid URL path.

## Navigate to the API definition
1. Change the value of the username parameter from `../administrator` to `../%23`. Notice the `Invalid route` response.
2. Incrementally add further `../` sequences until you reach `../../../../%23` Notice that this returns a `Not found` response. This indicates that you've navigated outside the API root.
3. At this level, add some common API definition filenames to the URL path. For example, submit the following:
	 `username=../../../../openapi.json%23
    `
    Notice that this returns an error message, which contains the following API endpoint for finding users:
    `/api/internal/v1/users/{username}/field/{field}`
    
    Notice that this endpoint indicates that the URL path includes a parameter called `field`.

## Exploit the vulnerability
1. Update the value of the `username` parameter, using the structure of the identified endpoint. Add an invalid value for the `field` parameter:
    `username=administrator/field/foo%23`
    Send the request. Notice that this returns an error message, because the API only supports the email field.

2. Add `email` as the value of the `field` parameter:
    `username=administrator/field/email%23`
    Send the request. Notice that this returns the original response. This may indicate that the server-side application recognizes the injected `field` parameter and that `email` is a valid field type.

3. In **Proxy > HTTP history**, review the `/static/js/forgotPassword.js` JavaScript file. Identify the password reset endpoint, which refers to the `passwordResetToken` parameter:
    `/forgot-password?passwordResetToken=${resetToken}`

4. In the **Repeater** tab, change the value of the `field` parameter from `email` to `passwordResetToken`:
    `username=administrator/field/passwordResetToken%23`
    Send the request. Notice that this returns an error message, because the `passwordResetToken` parameter is not supported by the version of the API that is set by the application.

5. Using the `/api/` endpoint that you identified earlier, change the version of the API in the value of the `username` parameter:
    `username=../../v1/users/administrator/field/passwordResetToken%23`
    Send the request. Notice that this returns a password reset token. Make a note of this.

6. In Burp's browser, enter the password reset endpoint in the address bar. Add your password reset token as the value of the `reset_token` parameter. For example:
    `/forgot-password?passwordResetToken=123456789
7. Set a new password.
8. Log in as the `administrator` using your password. Go to the **Admin panel** and delete `carlos` to solve the lab.

Analysis (easy way):

![[Pasted image 20241027015139.png]]
![[Pasted image 20241027014947.png]]
![[Pasted image 20241027015327.png]]
![[Pasted image 20241027015531.png]]
![[Pasted image 20241027015828.png]]
![[Pasted image 20241027015922.png]]

- we can use burp intruder to see other interesting API endpoints as: `openapi.json`
![[Pasted image 20241027020332.png]]

- make note of this: `/api/internal/v1/users/{username}/field/{field}`
![[Pasted image 20241027020921.png]]

- make note of this: `**This version of API** only supports the email field for security reasons`
![[Pasted image 20241027021152.png]]
![[Pasted image 20241027021241.png]]

- having in mind last note: `/api/internal/v1/users/{username}/field/{field}` we will do a path traversal to the specified version that will allow us to extract `passwordResetToken` value:
![[Pasted image 20241027021810.png]]


