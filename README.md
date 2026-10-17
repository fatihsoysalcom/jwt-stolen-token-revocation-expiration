# JWT Stolen Token Revocation Expiration

This example demonstrates the security implications of stolen JSON Web Tokens (JWTs) and how to mitigate them. It shows how a long-lived token, if stolen, can be used by an attacker even after the legitimate user logs out, and introduces a server-side revocation mechanism (blacklist) to prevent this. It also illustrates the role of short-lived tokens and automatic expiration in reducing the attack window.

## Language

`python`

## How to Run

1. Ensure you have Python 3 installed.
2. Install the PyJWT library: `pip install PyJWT`
3. Save the code as `main.py`.
4. Run from your terminal: `python main.py`

## Original Article

This example accompanies the Turkish article: [7 Günlük JWT: Çalındığında Neler Olur ve Nasıl Korunuruz?](https://fatihsoysal.com/blog/7-gunluk-jwt-calindiginda-neler-olur-ve-nasil-korunuruz/).

## License

MIT — see [LICENSE](LICENSE).
