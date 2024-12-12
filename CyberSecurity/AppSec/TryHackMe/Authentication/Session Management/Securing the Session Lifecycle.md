
## Session Creation
Session creation is where the most vulnerabilities can creep in. Modern frameworks reduce weak session vulnerabilities, but with AI-driven coding tools, these issues are re-emerging. Key session risks include:
- **Weak Session Values:** Custom session creation can result in guessable session IDs, like base64-encoded usernames, making account hijacking easier if reverse-engineered.
- **Controllable Session Values:** Tokens like JWTs can be exploited if not properly secured or verified, allowing attackers to generate their own valid tokens.
- **Session Fixation:** If a session ID isn't updated after login, attackers can hijack a user's session by capturing the pre-authentication session value.
- **Insecure Session Transmission:** In environments using SSO, session data is transferred between servers. Vulnerabilities, like insecure redirects, can expose session data, allowing attackers to hijack sessions.

## Session Tracking
Session tracking is the second largest culprit of vulnerabilities.

**Authorization Bypass**
Authorization Bypass occurs when a system fails to properly check if a user has permission to perform a requested action. There are two types:

- *Vertical Bypass:* A user gains access to actions meant for more privileged users.
- *Horizontal Bypass:* A user performs allowed actions but on data they shouldn’t have access to, such as modifying another user’s information.

Vertical bypasses are easier to prevent using access controls and function checks, while horizontal bypasses require additional code to verify the user's identity and data permissions.

**Insufficient Logging**
Insufficient Logging can hinder investigations after an attack. Application-level logs are critical to track user actions and associate them with specific sessions. Both accepted and rejected actions should be logged, as legitimate-looking actions (like in session hijacking) might hide malicious intent.

## Session Expiry
Session expiry becomes a vulnerability when session durations are too long. Think of a session like a movie ticket—it should only be valid for a specific time. Shorter session lifetimes are crucial for sensitive applications, like banking, while longer sessions may be acceptable for services like webmail.

For long-lasting sessions, security can be enhanced by tracking the session’s **location**. If the session is accessed from a different location, it may indicate **session hijacking**, and the session should be terminated to protect the user.

## Session Termination
Session termination becomes a problem if sessions aren't properly closed on the server when a user logs out. If an attacker hijacks a session, the user needs server-side session invalidation to block the attacker’s access.

For tokens with embedded lifetimes, sessions can’t be easily revoked, but adding tokens to a **blocklist** can help. Some applications allow users to view and manually terminate all active sessions. It’s also best practice to **terminate all sessions** after a successful password reset, ensuring the user regains full control of their account.
