# jwt-stolen-token-revocation-expiration
This example demonstrates the security implications of stolen JSON Web Tokens (JWTs) and how to mitigate them. It shows how a long-lived token, if stolen, can be used by an attacker even after the legitimate user logs out, and introduces a server-side revocation mechanism (blacklist) to prevent this. It also illustrates the role of short-lived toke
