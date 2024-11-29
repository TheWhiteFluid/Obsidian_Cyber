Application Programming Interfaces, or APIs for short, have become incredibly popular today. One of the key reasons for this boom is the ability to create a single API that can then serve several different interfaces, such as a web application and mobile application, at the same time. This allows the same server-side logic to be centralized and reused for all interfaces. From a security perspective, this is also usually beneficial as it means we can implement the server-side security in a single API that would then protect our server regardless of the interface that is being used.

However, new session management methods were also created with the rise of APIs. As cookies are usually associated with web applications used through a browser, cookie-based authentication for APIs usually doesn't work as well since the solution is then not agnostic for other interfaces. This is where token-based session management comes in to save the day.


## Token-Based Session Management
Token-based session management is a relatively new concept. Instead of using the browser's automatic cookie management features, it relies on client-side code for the process. After authentication, the web application provides a token within the request body. Using client-side JavaScript code, this token is then stored in the browser's LocalStorage.

When a new request is made, JavaScript code must load the token from storage and attach it as a header. One of the most common types of tokens is JSON Web Tokens (JWT), which are passed through the `Authorization: Bearer` header. However, as we are not using the browser's built-in cookie management features, it is a bit of the wild west where anything goes. Although there are standards, nothing is forcing anything from sticking to these standards. Tokens like JWTs are a way to standardise token-based session management.


## API Project
During this room, you will perform exploitation against several APIs. APIs can be documented using several different methods. One popular method is creating a [Postman](https://www.postman.com/) project or a [Swagger](https://swagger.io/) file. While we encourage you to experiment with these solutions, they require you to have an account, which we avoid forcing in this room. Instead, a simplified explanation of the API is provided below. The API remains consistent for all examples except for the last one, which has additional features. As you work through the exercises, refer to this section for guidance. The API was developed in Python Flask. As such, the coding examples will be in Python.

**API Endpoints**  
The API project has a single API endpoint, namely [http://MACHINE_IP/api/v1.0/exampleX](http://machine_ip/api/v1.0/exampleX). The `X` is replaced by the number of the example. This endpoint accesses two HTTP methods:
- **POST**: To authenticate and receive your JWT, you need to make a POST request with the credentials provided in JSON format.
- **GET**: To get details about your user and ultimately perform the privilege escalation to recover your task flag.

**API Credentials**
To authenticate to the API, a JSON body with the credentials needs to be sent as follows:
- **username**: user
- **password**: passwordX

The `X` needs to be replaced with the number of the example.


**API Examples**
Below are the two cURL requests you can use to interface with the API. For authentication, the following cURL request can be made:

```
`curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "passwordX" }' http://10.10.210.48/api/v1.0/exampleX`  
```

For user verification, the following cURL request can be made:
```
`curl -H 'Authorization: Bearer {JWT token}' http://10.10.210.48/api/v1.0/exampleX?username=Y`
```

The `[JWT token]` component has to be replaced with the JWT received from the first request. In this case, `Y` can be either `user` or `admin`, depending on your permissions.

**API Permissions**
The main goal in each example is to gain admin privileges and verify these permissions. Once you have a valid JWT where admin is set to 1, you can request the details of the admin user. This will return your flag. The process will be shown for the first example, but you will have to copy the steps for the rest of the examples.