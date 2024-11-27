To understand the common vulnerabilities in session management, we first need to examine authentication and authorisation. While they sound the same and are often confused, each plays a critical and unique role in session management. To better explain the differences, let's examine the *IAAA(Identification-Authentication-Authorisation-Accountability)* model:
![](Pasted%20image%2020241127082107.png)

**Identification**
Identification is the process of verifying who the user is. This starts with the user claiming to be a specific identity. In most web applications, this is performed by submitting your username. You are claiming that you are the person associated with the specific username. Some applications use uniquely created usernames, whereas others will take your email address as the username.

**Authentication**
Authentication is the process of ensuring that the user is who they say they are. Where in identification, you provide a username, for authentication, you provide proof that you are who you say you are. For example, you can supply the password associated with the claimed username. The web application can confirm this information if it is valid; this is the point where session creation would kick in.

**Authorisation**
Authorisation is the process of ensuring that the specific user has the rights required to perform the action requested. For example, while all users may view data, only a select few may modify it. In the session management lifecycle, session tracking plays a critical role in authorisation.

**Accountability**
Accountability is the process of creating a record of the actions performed by users. We should track the user's session and log all actions performed using the specific session. This information plays a critical role in the event of a security incident to piece together what has happened.


*IAAA and Session Management*
Authentication plays a role in how sessions are created. Authorisation becomes important to verify that the user associated with a specific session has the permission to perform the action they are requesting. Accountability is crucial for us to piece together what actually occurred in an incident, which means it is important that requests are logged and that the session associated with each request is also logged.