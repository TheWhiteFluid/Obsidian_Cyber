
## Same-Origin Policy (SOP)
Same-origin policy, also known as SOP, is a security measure restricting web pages from interacting with resources from different origins. An origin is defined by the scheme (protocol), hostname (domain), and URL port.

1. **Scheme (Protocol)** – e.g., `http://` or `https://`
2. **Hostname (Domain)** – e.g., `example.com`
3. **Port** – e.g., `:80`, `:443`, or any other specified port

| URL 1                     | URL 2                      | Same Origin? | Reason                                 |
| ------------------------- | -------------------------- | ------------ | -------------------------------------- |
| `https://example.com`     | `https://example.com`      | ✅ Yes        | Same scheme, domain, and port          |
| `https://example.com:443` | `https://example.com`      | ✅ Yes        | Default HTTPS port (443)               |
| `http://example.com`      | `https://example.com`      | ❌ No         | Different schemes (`http` vs. `https`) |
| `https://example.com`     | `https://sub.example.com`  | ❌ No         | Different subdomains                   |
| `https://example.com`     | `https://example.com:8443` | ❌ No         | Different ports                        |

### **How SOP Works**
- If `https://example.com` loads a script, it **can only** make requests to `https://example.com`
- If it tries to fetch data from `https://api.otherdomain.com`, the browser **blocks** the request.

 ### **Why SOP Exists**
- It **prevents malicious scripts** from accessing sensitive user data on different sites.
- Example: If you are logged into `bank.com`, SOP prevents a malicious script from `evil.com` from reading your `bank.com` data.

## Cross-Origin Resource Sharing (CORS)
Cross-Origin Resource Sharing, also known as CORS, is a mechanism that allows web applications to request resources from different domains securely. This is crucial in web security as it prevents malicious scripts on one page from obtaining access to sensitive data on another web page through the browser.

**Cross-Origin Resource Sharing (CORS)** is a **mechanism that allows exceptions to SOP**, enabling web applications to access resources from different origins **if the server permits it**.

### **How CORS Works**
- When a browser tries to make a **cross-origin request**, the server can include specific **CORS headers** in its response to **allow or deny** the request.
- Without CORS, the browser **blocks the request** due to **SOP**.

If a frontend site at `https://example.com` wants to fetch data from `https://api.otherdomain.com`, the **server** at `api.otherdomain.com` must include:

```
Access-Control-Allow-Origin: https://example.com

# or

Access-Control-Allow-Origin: *  # (Allows any domain)
```

### **CORS Request Example (Fetch API)**
``` javascript
fetch("https://api.otherdomain.com/data")
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error("CORS Error:", error));
```


## **Key Differences: SOP vs. CORS**

| Feature               | Same-Origin Policy (SOP)                  | Cross-Origin Resource Sharing (CORS)           |
| --------------------- | ----------------------------------------- | ---------------------------------------------- |
| **Purpose**           | Restricts access to same-origin resources | Allows controlled cross-origin access          |
| **Default Behavior**  | Blocks cross-origin requests              | Blocks unless explicitly allowed by the server |
| **Control Location**  | Enforced by the **browser**               | Controlled by the **server** via HTTP headers  |
| **Bypass Mechanisms** | CORS, JSONP, Reverse Proxy                | CORS Headers (`Access-Control-Allow-Origin`)   |

