Thinking about your interactions with web applications, you should realise that you do not provide a web application with your username and password on every request. Instead, after authentication, you are provided with a session. This session is used by the web application to keep your state, track your actions, and decide whether or not you are allowed to do what you are trying to do. Session management aims to ensure that these steps are performed correctly. Otherwise, it may be possible for a threat actor to compromise your session and effectively hijack it!

Sessions are, therefore, used to track users throughout their use of a web application. Session management is the process of managing these sessions and ensuring that they remain secure.

## Lifecycle
![](Pasted%20image%2020241127081209.png)

**Session Creation**
You might think this first step in the lifecycle occurs only after you provide your credentials, such as a username and password. However, on many web applications, the initial session is already created when you visit the application. This is because some applications want to track your actions even before authentication. Once you provide your username and password, you receive a session value that is then sent with each new request. How these session values are generated, used, and stored is crucial in securing session creation.

**Session Tracking**
Once you receive your session value, this is submitted with each new request. This allows the web application to track your actions even though the HTTP protocol is stateless in nature. With each request made, the web application can recover the session value from the request and perform a server-side lookup to understand who the session belongs to and what permissions they have. In the event that there are issues in the session tracking process, it may allow a threat actor to hijack a session or impersonate one.

**Session Expiry**
Because the HTTP protocol is stateless, it may happen that a user of the web application all of a sudden stops using it. For example, you might close the tab or your entire browser. Since the protocol is stateless, the web application has no method to know that this action has occurred. This is where session expiry comes into play. Your session value itself should have a lifetime attached to it. If the lifetime expires and you submit an old session value to the web application, it should be denied as the session should have been expired. Instead, you should be redirected to the login page to authenticate again and start the session management lifecycle all over again!

**Session Termination**
However, in some cases, the user might forcibly perform a logout action. In the event that this occurs, the web application should terminate the user's session. While this is similar to session expiry, it is unique in the sense that even if the session's lifetime is still valid, the session itself should be terminated. Issues in this termination process could allow a threat actor to gain persistent access to an account.