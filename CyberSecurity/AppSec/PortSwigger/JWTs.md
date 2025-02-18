- https://portswigger.net/web-security/jwt
- https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html

## 1. JWT authentication bypass via unverified signature
This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
- **Log in** to your account in the lab.
- **Check JWT token** in Burp's **Proxy > HTTP history** after logging in.
- **Decode JWT** in the **Inspector panel** and note the `sub` claim (your username).
- **Send request to Burp Repeater**, modify the path to `/admin`, and check access restrictions.
- **Edit JWT payload**, changing `sub` from `wiener` to `administrator`, then apply changes.
- **Resend the request** to access the **admin panel** successfully.
- **Find and send the delete request** (`/admin/delete?username=carlos`) to solve the lab.
