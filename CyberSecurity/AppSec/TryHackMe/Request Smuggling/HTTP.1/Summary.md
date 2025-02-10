---
NotionID-: 1951aa85-ad05-81ac-ba4c-f8a5fa89e8c6
link-: https://www.notion.so/Summary-1951aa85ad0581acba4cf8a5fa89e8c6
---

## Components of Modern Web Applications
Modern web applications are no longer straightforward, monolithic structures. They are composed of different components that work with each other. Below are some of the components that a modern web application usually consists of:

1. **Front-end server**: This is usually the reverse proxy or load balancer that forwards the requests to the back-end.
2. **Back-end server**: This server-side component processes user requests, interacts with databases, and serves data to the front-end. It's often developed using languages like PHP, Python, and Javascript and frameworks like Laravel, Django, or Node.js.
3. **Databases**: Persistent storage systems where application data is stored. Examples of this are databases like MySQL, PostgreSQL, and NoSQL.
4. **APIs (Application Programming Interfaces)**: Interfaces allow the front and back-end to communicate and integrate with other services.
5. **Microservices**: Instead of a single monolithic back-end, many modern applications use microservices, which are small, independent services that communicate over a network, often using HTTP/REST or gRPC.

## Load Balancers and Reverse Proxies
1. **Load Balancers**: These devices or services distribute incoming network traffic across multiple servers to ensure no single server is overwhelmed with too much traffic. This distribution ensures high availability and reliability by redirecting requests only to online servers that can handle them. Load balancing for web servers is often done by reverse proxies. Examples include *AWS Elastic Load Balancing*, *HAProxy*, and F5 BIG-IP.
2. **Reverse Proxies**: A reverse proxy sits before one or more web servers and forwards client requests to the appropriate web server. While they can also perform load balancing, their primary purpose is to provide a single access point and control for back-end servers. Examples include *NGINX*, Apache with mod_proxy, and Varnish.

![](Pasted%20image%2020250209104620.png)

## Role of Caching Mechanisms
Caching is a technique used to store and reuse previously fetched data or computed results to speed up subsequent requests and computations. In the context of web infrastructure:

3. **Content Caching**: By storing web content that doesn't change frequently (like images, CSS, and JS files), caching mechanisms can reduce the load on web servers and speed up content delivery to users.
4. **Database Query Caching**: Databases can cache the results of frequent queries, reducing the time and resources needed to fetch the same data repeatedly.
5. **Full-page Caching**: Entire web pages can be cached, so they don't need to be regenerated for each user. This is especially useful for websites with high traffic.
6. **Edge Caching/CDNs**: Content Delivery Networks (CDNs) cache content closer to the users (at the "edge" of the network), reducing latency and speeding up access for users around the world.
7. **API Caching**: Caching the responses can significantly reduce back-end processing for APIs that serve similar requests repeatedly.
	![](Pasted%20image%2020250209104756.png)

Caching, when implemented correctly, can significantly enhance the performance and responsiveness of web applications. However, managing caches properly is essential to avoid serving stale or outdated content.


## HTTP Request Structure
Every HTTP request comprises two main parts: the header and the body.
	![](Pasted%20image%2020250209105113.png)

8. **Request Line**: The first line of the request `POST /admin/login HTTP/1.1` is the request line. It consists of at least three items. First is the method, which in this case is "POST". The method is a one-word command that tells the server what to do with the resource. Second is the path component of the URL for the request. The path identifies the resource on the server, which in this case is "/admin/login". Lastly, the HTTP version number shows the HTTP specification to which the client has tried to make the message comply. Note that HTTP/2 and HTTP/1.1 have different structures.
9. **Request Headers**: This section contains metadata about the request, such as the type of content being sent, the desired response format, and authentication tokens. It's like the envelope of a letter, providing information about the sender, receiver, and the nature of the content inside.
10. **Message Body**: This is the actual content of the request. The body might be empty for a GET request, but for a POST request, it could contain form data, JSON payloads, or file uploads.

### **Content-Length Header**
The Content-Length header indicates the request or response body size in bytes. It informs the receiving server how much data to expect, ensuring the entire content is received.

Content-Length Sample Request
```shell-session
POST /submit HTTP/1.1
Host: good.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 14
    
q=smuggledData
```

### **Transfer-Encoding Header**
The Transfer-Encoding header is used to specify the form of encoding applied to the message body of an HTTP request or response. A commonly used value for this header is "chunked", indicating that the message body is divided into a series of chunks, each preceded by its size in hexadecimal format. Other possible values for the Transfer-Encoding header include "compress", "deflate", and "gzip", each indicating a different type of encoding. 

Transfer-Encoding Sample Request
```shell
POST /submit HTTP/1.1
Host: good.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
    
b
q=smuggledData 
0
```

In this example:
- "b" (in hexadecimal, equivalent to 11 in decimal) specifies the size of the following chunk.
-  the chunk `q=smuggledData` is the actual data, followed by a new line.
 - "0"  indicating the end of the message body. Each chunk size is given in hexadecimal format, and the end of the chunked body is signified by a chunk of size 0.


## How Headers Affect Request Processing
Headers play an important role in guiding the server to process the request. This is because they determine how to parse the request body and influence caching behaviours. They can also affect authentication, redirection, and other server responses.
	![](Pasted%20image%2020250209112351.png)
Manipulating headers like Content-Length and Transfer-Encoding can create vulnerabilities. For instance, if a proxy server gets confused by these headers, it might not properly distinguish where one request ends and another starts.


## HTTP Request Smuggling Origin
HTTP Request Smuggling primarily occurs due to discrepancies in how different servers (like a front-end server and a back-end server) interpret HTTP request boundaries. For example:

1. If both Content-Length and Transfer-Encoding headers are present, ambiguities can arise.
2. Some components prioritize Content-Length, while others prioritize Transfer-Encoding.
3. This discrepancy can lead to one component believing the request has ended while another thinks it's still ongoing, leading to smuggling.

**Example:** 
	Suppose a front-end server uses the Content-Length header to determine the end of a request while a back-end server uses the Transfer-Encoding header. An attacker can craft a request that appears to have one boundary to the front-end server but a different boundary to the back-end server. This can lead to one request being "smuggled" inside another, causing unexpected behaviour and potential vulnerabilities.
	![](Pasted%20image%2020250209112556.png)
