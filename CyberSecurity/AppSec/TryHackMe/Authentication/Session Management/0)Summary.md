To defend against these attacks, it is important to implement a secure session management lifecycle. While several items were touched on in this room, let's take a look at a recap:

### Key Takeaways
- The session's values must be stored securely, regardless of being a cookie or a token.
- The session values themselves must be either sufficiently random and non-guessable or use a signing mechanism to ensure that they cannot be tampered with.
- Sessions should be used to track user actions and perform authorisation checks to ensure the user can perform the requested action.
- Sessions should expire after a set amount of time to prevent them from being used for persistent access.
- If the logout button is pressed, the session should be removed client-side and invalidated server-side. Otherwise, a user would be unable to destroy their session if it was compromised.