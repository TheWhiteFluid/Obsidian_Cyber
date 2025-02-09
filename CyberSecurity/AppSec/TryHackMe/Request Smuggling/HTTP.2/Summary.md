The second version of the HTTP protocol proposes several changes over the original HTTP specifications. The new protocol intends to overcome the problems inherent to HTTP/1.1 by changing the message format and how the client and server communicate. One of the significant differences is that HTTP/2 requests and responses use a completely binary protocol, unlike HTTP/1.1, which is humanly readable. This is a massive improvement over the older version since it allows any binary information to be sent in a way that is easier for machines to parse without making mistakes.

While the HTTP/2 binary format is difficult to read for humans, we will use a simplified representation of requests throughout the room. Here's a visual representation of HTTP/2 requests compared with an HTTP/1.1 request:
	![](Pasted%20image%2020250209171053.png)

also consider: https://www.catchpoint.com/http3-vs-http2

## **HTTP/3 vs HTTP/2**

| Concept                           | HTTP/2                                                                                                | HTTP/3                                                                                                                           |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Protocol                          | Transmission Control Protocol(TCP) offers reliability but suffers from head-of-line blocking.         | Quick UDP Internet Connections (QUIC) reduces latency and avoids TCP head-of-line blocking issues.                               |
| Multiplexing                      | Supports multiplexing and allows multiple requests and responses to be sent over a single connection. | Supports and optimizes multiplexing capabilities. Stream prioritization is more flexible and efficient.                          |
| Connection establishment          | TCP three-way handshake for connection establishment, which can add latency.                          | QUIC combines cryptographic and transport handshakes.                                                                            |
| Security                          | Encourages TLS for encryption but does not require it.                                                | Incorporates TLS 1.3 by default                                                                                                  |
| Performance                       | Performance improvements through header compression and server push.                                  | Builds on header compression with QUIC, offering enhancements in speed and reliability                                           |
| Error recovery                    | TCP error recovery mechanisms can be slow.                                                            | QUIC novel error recovery features like forward error correction(FEC) minimize congestion and control the impact of packet loss. |
| Server push                       | Yes                                                                                                   | Yes                                                                                                                              |
| Mobility and global accessibility | Mobility between networks requires re-establishment.                                                  | Supports connection migration. So websites and online services work well for everyone, everywhere.                               |

The HTTP/2 request has the following components:

- **Pseudo-headers:** HTTP/2 defines some headers that start with a colon `:`. Those headers are the minimum required for a valid HTTP/2 request. In our image above, we can see the `:method`, `:path`, `:scheme` and `:authority` pseudo-headers.
- **Headers:** After the pseudo-headers, we have regular headers like `user-agent` and `content-length`. Note that HTTP/2 uses lowercase for header names.
- **Request Body:** Like in HTTP/1.1, this contains any additional information sent with the request, like POST parameters, uploaded files and other data.

Another important change in the structure of a request that may not be obvious is that HTTP/2 establishes precise boundaries for each part of a request or response. Instead of depending on specific characters like `\r\n` to separate different headers or `:` to separate the header name from the header value like HTTP/1, HTTP/2 adds fields to track the size of each part of a request (or response).


## Request Smuggling and HTTP/2

One of the main reasons HTTP request smuggling is possible in HTTP/1 scenarios is the existence of several ways to define the size of a request body. This ambiguity in the protocol leads to different proxies having their own interpretation of where a request ends and the next one begins, ultimately ending in request smuggling scenarios.

The second version of the HTTP protocol was built to improve on many of the characteristics of the first version. The one we most notably care about in the context of HTTP request smuggling is the clear definition of sizes for each component of an HTTP request. To avoid the ambiguities in HTTP/1, HTTP/2 prefixes each request component with a field that contains its size. For example, each header is prefixed with its size, so parsers know precisely how much information to expect. To understand this better, let's take a look at a captured request in Wireshark, looking specifically at the request headers:

![](Pasted%20image%2020250209171946.png)

In the image, we are looking at the `:method` pseudo-header. As we can see, both the header name and value are prefixed with their corresponding lengths. The header name has a length of 7, corresponding to `:method` and the header value has a length of 3, corresponding to the string `GET`.

The request's body also includes a length indicator, rendering headers like `Content-Length` and `Transfer-Encoding: chunked` meaningless in pure HTTP/2 environments.

**Note:** 
	Even though `Content-Length` headers aren't directly used by HTTP/2, modern browsers will still include them for a specific scenario where HTTP downgrades may occur. This is very important for our specific scenario and we will discuss it in more detail in the following tasks.

With such clear boundaries for each part of a request, one would expect request smuggling to be impossible, and to a certain extent, it is in implementations that rely solely on HTTP/2. However, as with any new protocol version, not all devices can be upgraded to it directly. This results in implementations of load balancers or reverse proxies that support HTTP/2, serving content from server farms that still use HTTP/1.