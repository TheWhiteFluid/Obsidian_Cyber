https://portswigger.net/web-security/web-cache-deception#constructing-a-web-cache-deception-attack

https://book.hacktricks.xyz/pentesting-web/http-response-smuggling-desync

- Web cache poisoning manipulates cache keys to inject malicious content into a cached response, which is then served to other users.
- Web cache deception exploits cache rules to trick the cache into storing sensitive or private content, which the attacker can then access.
# 1. Exploiting path mapping for web cache deception
To solve the lab, find the API key for the user `carlos`. You can log in to your own account using r the following credentials: `wiener:peter`.

## Identify a path mapping discrepancy
1. In **Proxy > HTTP history**, right-click the `GET /my-account` request and select **Send to Repeater**. Go to the **Repeater** tab. Add an arbitrary segment to the base path, for example change the path to `/my-account/abc`.
2. Send the request. Notice that you still receive a response containing your API key. This indicates that the origin server abstracts the URL path to `/my-account`.
3. Add a static extension to the URL path, for example `/my-account/abc.js`. Send the request. Notice that the response contains the `X-Cache: miss` and `Cache-Control: max-age=30` headers. The `X-Cache: miss` header indicates that this response wasn't served from the cache. The `Cache-Control: max-age=30` header suggests that if the response has been cached, it should be stored for 30 seconds.
4. Resend the request within 30 seconds. Notice that the value of the `X-Cache` header changes to `hit`. This shows that it was served from the cache. From this, we can infer that the cache interprets the URL path as `/my-account/abc.js` and has a cache rule based on the `.js` static extension. You can use this payload for an exploit.
## Craft an exploit
1. In Burp's browser, click **Go to exploit server**.
2. In the **Body** section, craft an exploit that navigates the victim user `carlos` to the malicious URL that you crafted earlier. Make sure to change the arbitrary path segment you added, so the victim doesn't receive your previously cached response:
    `<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js"</script>`
3. Click **Deliver exploit to victim**. When the victim views the exploit, the response they receive is stored in the cache.
4. Go to the URL that you delivered to `carlos` in your exploit:
    `https://YOUR-LAB-ID.web-security-academy.net/my-account/wcd.js`
5. Notice that the response includes the API key for `carlos`.

Analysis:
![[Pasted image 20241028150252.png]]
![[Pasted image 20241028150357.png]]
![[Pasted image 20241028150544.png]]

Exploit:
```
<script> document.location="https://0af20010046e1a4f81bbf136014c0061.exploit-server.net/my-account/nbyte2.css" </script>
```
- used another endpoint thus previous one was already cached by the server.

# **2. Exploiting path delimiters for web cache deception**
To solve the lab, find the API key for the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`. We have provided a list of possible delimiter characters to help you solve the lab: [Web cache deception lab delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list).
## Identify path delimiters used by the origin server
1. In **Proxy > HTTP history**, right-click the `GET /my-account` request and select **Send to Repeater**.
2. Go to the **Repeater** tab. Add an arbitrary segment to the path. For example, change the path to `/my-account/abc`.
3. Send the request. Notice the `404 Not Found` response with no evidence of caching. This indicates that the origin server doesn't abstract the path to `/my-account`.
4. Remove the arbitrary segment and add an arbitrary string to the original path. For example, change the path to `/my-accountabc`.
5. Send the request. Notice the `404 Not Found` response with no evidence that the response was cached. You'll use this response as a reference to help you identify characters that aren't used as delimiters.
6. Right-click the request and select **Send to Intruder**.
7. Go to the **Intruder** tab. Make sure that **Sniper attack** is selected and add a payload position after `/my-account` as follows: `/my-account§§abc`.
8. In the **Payloads** side panel, under **Payload configuration**, add a list of characters that may be used as delimiters.
9. Under **Payload encoding**, deselect **URL-encode these characters**.
10. Click  **Start attack**. The attack runs in a new window.
11. When the attack finishes, sort the results by **Status code**. Notice that the `;` and `?` characters receive a `200` response with your API key. All other characters receive the `404 Not Found` response. This indicates that the origin server uses `;` and `?` as path delimiters.
## Investigate path delimiter discrepancies
1. Go to the **Repeater** tab that contains the `/my-accountabc` request.
2. Add the `?` character after `/my-account` and add a static file extension to the path. For example, update the path to `/my-account?abc.js`.
3. Send the request. Notice that the response doesn't contain evidence of caching. This may indicate that the cache also uses `?` as a path delimiter.
4. Repeat this test using the `;` character instead of `?`. Notice that the response contains the `X-Cache: miss` header.
5. Resend the request. Notice that the value of the `X-Cache` header changes to `hit`. This indicates that the cache doesn't use `;` as a path delimiter and has a cache rule based on the `.js` static extension. You can use this payload for an exploit.
## Craft an exploit
1. In Burp's browser, click **Go to exploit server**.
2. In the **Body** section, craft an exploit that navigates the victim user `carlos` to the malicious URL you crafted earlier. Make sure to change the arbitrary string, so the cache creates a unique key and `carlos` caches their account details instead of receiving your previously cached response:
    `<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/my-account;wcd.js"</script>`
3. Click **Deliver exploit to victim**. When the victim views the exploit, the response they receive is stored in the cache.
4. Go to the URL that you delivered to `carlos`:
    `https://YOUR-LAB-ID.web-security-academy.net/my-account;wcd.js`
5. Notice that the response includes the API key for `carlos`. 

Analysis:
![[Pasted image 20241028153345.png]]

![[Pasted image 20241028155446.png]]
![[Pasted image 20241028155626.png]]

- fuzzing path delimiter
![[Pasted image 20241028155743.png]]
	![[Pasted image 20241028160147.png]]
![[Pasted image 20241028160203.png]]

![[Pasted image 20241028160325.png]]
	![[Pasted image 20241028160437.png]]

Exploit:
```
<script> window.location="https://0a2900c90343f9d082757f9100360071.web-security-academy.net/my-account;test3.js" </script>
```

# **3. Exploiting origin server normalization for web cache deception**
To solve the lab, find the API key for the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`. We have provided a list of possible delimiter characters to help you solve the lab: [Web cache deception lab delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list).
## Investigate path delimiter discrepancies
1. In **Proxy > HTTP history**, right-click the `GET /my-account` request and select **Send to Repeater**.
2. Go to the **Repeater** tab. Change the path to `/my-account/abc`, then send the request. Notice the `404 Not Found` response. This indicates that the origin server doesn't abstract the path to `/my-account`.
3. Change the path to `/my-accountabc`, then send the request. Notice that this returns a `404 Not Found` response with no evidence of caching.
4. Right-click the message and select **Send to Intruder**.
5. Go to the **Intruder** tab. Make sure that **Sniper attack** is selected and add a payload position after `/my-account` as follows: `/my-account§§abc`.
6. In the **Payloads** side panel, under **Payload configuration**, add a list of characters that may be used as delimiters. Under **Payload encoding**, deselect **URL-encode these characters**.
7. Click  **Start attack**. The attack runs in a new window.
8. When the attack finishes, sort the results by **Status code**. Notice that only the `?` character receives a `200` response with your API key. This indicates that the origin server only uses `?` as a path delimiter. As `?` is generally universally used as a path delimiter, move on to investigate normalization discrepancies.
## Investigate normalization discrepancies
1. In **Repeater**, remove the arbitrary `abc` string and add an arbitrary directory followed by an encoded dot-segment to the start of the original path. For example, `/aaa/..%2fmy-account`
2. Send the request. Notice that this receives a `200` response with your API key. This indicates that the origin server decodes and resolves the dot-segment, interpreting the URL path as `/my-account`.
3. In **Proxy > HTTP history**, notice that the paths for static resources all start with the directory prefix `/resources`. Notice that responses to requests with the `/resources` prefix show evidence of caching.
4. Right-click a request with the prefix `/resources` and select **Send to Repeater**.
5. In **Repeater**, add an encoded dot-segment after the `/resources` path prefix, such as `/resources/..%2fYOUR-RESOURCE`.
6. Send the request. Notice that the `404` response contains the `X-Cache: miss` header.
7. Resend the request. Notice that the value of the `X-Cache` header changes to `hit`. This may indicate that the cache doesn't decode or resolve the dot-segment and has a cache rule based on the `/resources` prefix. To confirm this, you'll need to conduct further testing. It's still possible that the response is being cached due to a different cache rule.
8. Modify the URL path after `/resources` to a arbitrary string as follows: `/resources/aaa`. Send the request. Notice that the `404` response contains the `X-Cache: miss` header.
9. Resend the request. Notice that the value of the `X-Cache` header changes to `hit`. This confirms that there is a static directory cache rule based on the `/resources` prefix.
## Craft an exploit
1. Go to the **Repeater** tab that contains the `/aaa/..%2fmy-account` request. Attempt to construct an exploit as follows: `/resources/..%2fmy-account`. Send the request. Notice that this receives a `200` response with your API key and the `X-Cache: miss` header.
2. Resend the request and notice that the value of the `X-Cache` header updates to `hit`.
3. In Burp's browser, click **Go to exploit server**.
4. In the **Body** section, craft an exploit that navigates the victim user `carlos` to a malicious URL. Make sure to add an arbitrary parameter as a cache buster, so the victim doesn't receive your previously cached response:
    `<script>document.location="https://YOUR-LAB-ID.web-security-academy.net/resources/..%2fmy-account?wcd"</script>`
5. Click **Deliver exploit to victim**. When the victim views the exploit, the response they receive is stored in the cache.
6. Go to the URL that you delivered to `carlos` in your exploit:
    `https://YOUR-LAB-ID.web-security-academy.net/resources/..%2fmy-account?wcd`
7. Notice that the response includes the API key for the user `carlos`. 

Analysis:

