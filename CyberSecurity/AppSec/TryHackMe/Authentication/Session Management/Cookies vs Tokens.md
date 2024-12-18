**Cookie-Based Session Management**
Cookie-based session management is often called the old-school way of managing sessions. Once the web application wants to begin tracking, in a response, the Set-Cookie header value will be sent. Your browser will interpret this header to store a new cookie value. Let's take a look at such a Set-Cookie header:

`Set-Cookie: session=12345;`  

Your browser will create a cookie entry for a cookie named `session` with a value of `12345` which will be valid for the domain where the cookie was received from. Several attributes can also be added to this header. If you want to learn more about all of them, please refer [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie), but some of the noteworthy ones are:
- **Secure** - Indicates to the browser that the cookie may only be transmitted over verified HTTPS channels. If there are certificate errors or HTTP is used, the cookie value will not be transmitted.
- **HTTPOnly** - Indicates to the browser that the cookie value may not be read by client-side JavaScript.
- **Expire** - Indicates to the browser when a cookie value will no longer be valid and should be removed.
- **SameSite** - Indicates to the browser whether(if) the cookie may be transmitted in cross-site requests to help protect against CSRF attacks.

Note:
	 In cookie-based authentication, the browser automatically decides when to send a cookie with a request. It checks the cookie’s domain and attributes, and if they match the request, the browser attaches the cookie. This happens automatically, without needing any extra JavaScript on the client side.

## Token-Based Session Management
Token-based session management is a relatively new concept. Instead of using the browser's automatic cookie management features, it relies on client-side code for the process. After authentication, the web application provides a token within the request body. Using client-side JavaScript code, this token is then stored in the browser's *LocalStorage*.

When a new request is made, JavaScript needs to retrieve the token from storage and attach it to the request header. A common type of token is a **JSON Web Token (JWT)**, which is usually sent in the **Authorization: Bearer** header. Unlike cookies, tokens don't use the browser's automatic handling, so there’s more flexibility—but also less enforcement of strict rules. While standards exist, they aren't always followed, making token management less predictable.


## Benefits and Drawbacks

| **Feature**             | **Cookie-Session Management**                                    | **Token-Based Session Management**                          |
| ----------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------- |
| **Automatic Handling**  | Automatically sent by the browser with each request.             | Must be manually attached to each request using JavaScript. |
| **Security Features**   | Can use attributes like `HttpOnly` and `Secure` for protection.  | No automatic protections; must be safeguarded manually.     |
| **CSRF Vulnerability**  | Vulnerable to CSRF attacks as cookies are sent automatically.    | Not vulnerable to CSRF, as tokens are not auto-sent.        |
| **Domain Restrictions** | Locked to a specific domain, limiting use in decentralized apps. | Works well in decentralized apps with flexible management.  |
| **Data Containment**    | Stores session IDs, requiring server-side validation.            | Can contain all verification data within the token itself.  |

