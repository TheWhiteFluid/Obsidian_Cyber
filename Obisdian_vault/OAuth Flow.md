The OAuth 2.0 flow begins when a user (Resource Owner) interacts with a client application (Client) and requests access to a specific resource. The client redirects the user to an authorization server, where the user is prompted to log in and grant access. If the user consents, the authorization server issues an authorization code, which the client can exchange for an access token. This access token allows the client to access the resource server and retrieve the requested resource on behalf of the user.
![](Pasted%20image%2020241201144227.png)
## Workflow
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
