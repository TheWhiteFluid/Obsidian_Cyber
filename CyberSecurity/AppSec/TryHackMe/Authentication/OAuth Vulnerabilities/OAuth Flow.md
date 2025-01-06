The OAuth 2.0 flow begins when a user (Resource Owner) interacts with a client application (Client) and requests access to a specific resource. The client redirects the user to an authorization server, where the user is prompted to log in and grant access. If the user consents, the authorization server issues an authorization code, which the client can exchange for an access token. This access token allows the client to access the resource server and retrieve the requested resource on behalf of the user.
![](Pasted%20image%2020241201144227.png)
## Example
We will discuss various steps of the OAuth workflow in detail, considering the same `CoffeeShopApp` example. 

We will use a customized version of the Django OAuth toolkit for the OAuth provider. It is very important to understand that when the term OAuth provider is used in the upcoming tasks, it means the third-party OAuth provider with which we want to integrate/authenticate. For example, in the case of `Login with FactBook`, FactBook is the OAuth provider. Moreover, in these tasks, the OAuth provider, the `CoffeeShopApp`, would remain the same; however, the clients (the app we want to integrate) will change in each task.

You can visit the URL [http://coffee.thm:8000/admin](http://coffee.thm:8000/admin) to see the login panel for the OAuth provider, which would remain the same throughout the room.   

![coffeeshopapp login screen](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1722242469426.png)  

We will be using the following credentials for the OAuth provider in this room:
- **Victim**: `victim:victim123`
- **Attacker**: `attacker:tesla@123`

Once logged in to your OAuth provider, you can log in on any other website just like you perform `Sign Up with Google` on X, Facebook, or any other website. 

Now visit the URL  [http://bistro.thm:8000](http://bistro.thm:8000/), which we will use to understand the OAuth workflow. We will understand the workflow by considering a person named Tom (you can use any of the above credentials for him) who would like to log in to a different website app using his `CoffeeShopApp` account.

### Authorization Request
Tom first visits the bistro URL  [http://bistro.thm:8000/oauthdemo](http://bistro.thm:8000/oauthdemo), where he wants to log in via `CoffeeShopApp`. When he clicks on **Login via OAuth**, `CoffeeShopApp` must first obtain his permission, so the application redirects Tom's browser to the authorization server with an authorization request.
	![](Pasted%20image%2020241201144616.png)
Click on **Login with OAuth**, and you will be redirected to the authorization server with the URL 
```
http://coffee.thm:8000/accounts/login/?next=/o/authorize/%3Fclient_id%3Dzlurq9lseKqvHabNqOc2DkjChC000QJPQ0JvNoBt%26response_type%3Dcode%26redirect_uri%3Dhttp%3A//bistro.thm%3A8000/oauthdemo/callback 
```
![](Pasted%20image%2020241201144834.png)

The bistro website initiates this process by redirecting Tom to the authorization server with the following parameters included in the URL:

- `response_type=code`: This indicates that `CoffeeShopApp` is expecting an authorization code in return.
- `state`: A CSRF token to ensure that the request and response are part of the same transaction.
- `client_id`: A public identifier for the client application, uniquely identifying `CoffeeShopApp`.
- `redirect_uri`: The URL where the authorization server will send Tom after he grants permission. This must match one of the pre-registered redirect URIs for the client application.
- `scope`: Specifies the level of access requested, such as viewing coffee orders.

By including these parameters, the bistro app ensures that the authorization server understands what is requested and where to send the user afterwards. Here is the Python code that redirects the user to the authorization server:

``` python
def oauth_login(request): 
	app = Application.objects.get(name="CoffeeApp") 
	redirect_uri = request.GET.get("redirect_uri", "http://bistro.thm:8000/oauthdemo/callback") 

	authorization_url = ( 
		f"http://coffee.thm:8000/o/authorize/?client_id={app.client_id}&response_type=code&redirect_uri={redirect_uri}" 
	) 

	return redirect(authorization_url)
```

### Authentication & Authorization
When Tom reaches the authorization server, he is prompted to log in using his credentials. This step ensures that the server can verify his identity. After successfully logging in, the authorization server asks Tom if he agrees to grant the bistro app access to his details. This consent step is crucial as it gives Tom transparency and control over which applications can access his data.

The process typically involves:
- **User Login**: Tom enters his username and password on the authorization server's login page.
- **Consent Prompt**: After authentication, the authorization server presents Tom with a consent screen detailing what `CoffeeShopApp` requests access to (e.g., viewing his coffee orders). Tom must then decide whether to grant or deny these permissions.

![](Pasted%20image%2020241201155200.png)

This dual-step process ensures that Tom's identity is authenticated and his explicit consent is obtained before any access is granted, maintaining security and user control over personal data.

### Authorization Response
If Tom agrees to grant access, the authorization server generates an **authorization code** (as also discussed in Task 4). The server then redirects Tom to the bistro website using the specified `redirect_uri`. The redirection includes the authorization code and the original state parameter to ensure the integrity of the flow.

The authorization server responds with the following:
- `code`: `CoffeeShopApp` will use the authorization code to request an access token.
- `state`: The CSRF token previously sent by `CoffeeShopApp` to validate the response.

An example authorization response would be `https://bistro.thm:8000/callback?code=AuthCode123456&state=xyzSecure123`.

This step ensures the authorization process is secure and the response is linked to the bistro's initial request. The authorization code is a temporary token that will be used in the next step to obtain an access token, allowing `CoffeeShopApp` to access Tom's profile details.


### Token Request
The bistro website exchanges the authorization code for an access token by requesting the authorization server’s token endpoint through a POST request with the following parameters:

- `grant_type`: type of grant being used; usually, it's set as `code` to specify authorization code as the grant type.
- `code`: The authorization code received from the authorization server.
- `redirect_uri`: This must match the original redirect URI provided in the authorization request.
- `client_id and client_secret`: Credentials for authenticating the client application.

Using the above parameters, the following code will make a token request to `/o/token` endpoint.
```python
#defining token url
token_url = "http://coffee.thm:8000/o/token/" 
	#fetching client credentials
    client_id = Application.objects.get(name="CoffeeApp").client_id
    client_secret = Application.objects.get(name="CoffeeApp").client_secret
    #setting the redirect URI
    redirect_uri = request.GET.get("redirect_uri", "http://bistro.thm:8000/oauthdemo/callback")
	
	#preparing data for the token request
    data = {
        "grant_type": "authorization_code", #OAuth flow
        "code": code,                       #authorization code
        "redirect_uri": redirect_uri,       #match the URI
        "client_id": client_id,             
        "client_secret": client_secret,
    }
    
    #setting the request headers 
    #encode client_id:client_secret pair in b64 format  
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()}',
    }
    
    #send the token request
    response = requests.post(token_url, data=data, headers=headers)
    #parsing the response
    tokens = response.json()
```

### Token Response
The authorization server authenticates the bistro website and validates the authorization code. Upon successful validation, the server responds with an `Access Token` and, optionally, a `Refresh Token`.

The authorization server's response includes the following:
- `access_token`: Token that will be used to access Tom's details.
- `token_type`: Typically "Bearer".
- `expires_in`: The duration in seconds for which the access token is valid.
- `refresh_token (optional)`: A token used to obtain new access tokens without requiring the user to log in again.


With the access token, the bistro website can now authenticate requests to the resource server to access Tom's profile details. The optional refresh token can be used to request a new access token once the current one expires, providing a seamless user experience by avoiding the need for Tom to log in repeatedly.

The bistro website has completed the OAuth 2.0 authorization workflow with the access token. This token is a credential allowing the app to access protected resources on Tom's behalf. Now, the bistro website can make authenticated requests to the resource server to retrieve Tom's profile. Each request to the resource server includes the **access token** in the authorization header, ensuring that the server recognizes and permits the access.
