https://portswigger.net/web-security/web-cache-deception#constructing-a-web-cache-deception-attack

https://book.hacktricks.xyz/pentesting-web/http-response-smuggling-desync

# 1. Exploiting path mapping for web cache deception
To solve the lab, find the API key for the user `carlos`. You can log in to your own account using r the following credentials: `wiener:peter`.

## Identify a target endpoint
1. In Burp's browser, log in to the application using the credentials `wiener:peter`.
2. Notice that the response contains your API key.
## Identify a path mapping discrepancy
1. In **Proxy > HTTP history**, right-click the `GET /my-account` request and select **Send to Repeater**.
2. Go to the **Repeater** tab. Add an arbitrary segment to the base path, for example change the path to `/my-account/abc`.
3. Send the request. Notice that you still receive a response containing your API key. This indicates that the origin server abstracts the URL path to `/my-account`.
4. Add a static extension to the URL path, for example `/my-account/abc.js`.
5. Send the request. Notice that the response contains the `X-Cache: miss` and `Cache-Control: max-age=30` headers. The `X-Cache: miss` header indicates that this response wasn't served from the cache. The `Cache-Control: max-age=30` header suggests that if the response has been cached, it should be stored for 30 seconds.
6. Resend the request within 30 seconds. Notice that the value of the `X-Cache` header changes to `hit`. This shows that it was served from the cache. From this, we can infer that the cache interprets the URL path as `/my-account/abc.js` and has a cache rule based on the `.js` static extension. You can use this payload for an exploit.
## Craft an exploit
1. In Burp's browser, click **Go to exploit server**.
2. In the **Body** section, craft an exploit that navigates the victim user `carlos` to the malicious URL that you crafted earlier. Make sure to change the arbitrary path segment you added, so the victim doesn't receive your previously cached response:
    `<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js"</script>`
3. Click **Deliver exploit to victim**. When the victim views the exploit, the response they receive is stored in the cache.
4. Go to the URL that you delivered to `carlos` in your exploit:
    `https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js`
5. Notice that the response includes the API key for `carlos`. Copy this.
6. Click **Submit solution**, then submit the API key for `carlos` to solve the lab.

Analysis:
