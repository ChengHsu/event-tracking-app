# event-tracking-app
An AppEngine application that keeps track of upcoming events with an emphasis on Authentication

## Pasword-Based Authentication
From the user’s perspective, there are two pages: they try to go to /, but get a login form instead. They fill it in, and then they get the main page (/).

From the server’s perspective, when the user is not yet authenticated, 4 distinct requests come in that are handled:
- A GET request for /. No valid session cookie, so it redirects the browser to /login instead.
- A GET request for /login. Returns the login form. Best if it includes a CSRF token.
- A POST request for /login containing the username and password (and CSRF cookie if you use one). Server checks password by running the appropriate function, creates and stores a session token, and sets a cookie containing that token.
- A GET request for /. Now it has the session cookie. The server finds that session token in the database, sees what user is in there, and provides that user’s main page content.

## OpenID Connect Client
OIDC 3-legged auth flow:
- Go to your site’s /login page
- Request /login
- Get back a login form with the link above inside of it. That link contains a bunch of information. Constant Client ID and redirect_uri, and random state and nonce.
- Click the “login with google” link (or similar)
- Request login page from Google (or other provider)
- Get back a login form or something where you can affirmatively say “yes, use this account to authenticate”.
Submit responses, get logged in.
- Responses get submitted to e.g., Google, which does the heavy lifting of authenticating.
- Google responds with a redirect that your browser intercepts and acts on immediately. That redirect goes to your site, the URI you specified.
- The browser sends a request to your site with the information from Google.
- Your site checks that the state matches what is expected, then
- Sends a request to Google with the code it got, asking for an actual access token. Only here is the client secret used.
- Google responds with the JWT (identity), access token, and nonce, which your site can check to ensure that it’s the expected nonce.
- Your site creates and stores a session token for the user in the JWT.
- Your site responds with a cookie containing the session token. Typically it will do this in a 302 redirect response that causes you to go to the main page of your site (because now you are logged in!)


