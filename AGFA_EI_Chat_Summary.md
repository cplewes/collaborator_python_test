# Summary: AGFA EI Chat Web App, Keycloak Authentication, and XMPP Messaging

## 🧠 1. AGFA EI Chat Web App Architecture

- The AGFA Collaborator chat app uses **BOSH (XMPP over HTTP)** to communicate with an XMPP server endpoint:
  ```
  https://abpei-hub-app-north.albertahealthservices.ca:7443/http-bind/
  ```
- Communication is performed using **XML stanzas** over HTTP POST requests.
- The web client uses an `Authorization: Bearer <token>` header to authenticate each BOSH request.
- Browser-originated requests contain headers like:
  - `Origin`, `Referer`, `User-Agent`, `Accept`, `Content-Type`, etc.
  - This may affect server behavior and compatibility.

---

## 🔐 2. Keycloak Authentication Flow

### Working Token Endpoint
The token is requested via a **password grant** flow using the following URL:
```
https://abpei-hub-app-north.albertahealthservices.ca/auth/realms/EI/protocol/openid-connect/token?targetIdp=LDAP1
```

### Required POST Parameters
```x-www-form-urlencoded
grant_type=password
client_id=netboot
username=<USERNAME>
password=<PASSWORD>
scope=openid
```

### Required Headers
```http
Content-Type: application/x-www-form-urlencoded
Origin: https://abpei-hub-app-north.albertahealthservices.ca
Referer: https://abpei-hub-app-north.albertahealthservices.ca/
User-Agent: Mozilla/5.0 ...
```

### Notes
- The `targetIdp=LDAP1` parameter **must** be included as a **query string**, not in the POST body.
- No `client_secret` is required for the `netboot` client.
- Failure to match the HAR-extracted header structure or omit `targetIdp` results in 401 Unauthorized.

---

## ✉️ 3. XMPP Server Interaction (via BOSH)

### Endpoint
```
POST https://abpei-hub-app-north.albertahealthservices.ca:7443/http-bind/
```

### BOSH Setup
- The BOSH connection is initialized with:
  ```xml
  <body content='text/xml; charset=utf-8'
        xmlns='http://jabber.org/protocol/httpbind'
        to='agfa.com'
        xml:lang='en'
        wait='60'
        hold='1'
        rid='123456'
        ver='1.6'
        xmlns:xmpp='urn:xmpp:xbosh'
        xmpp:version='1.0'/>
  ```

### SASL Auth
- After connection, authentication is performed using:
  ```xml
  <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>
      base64("\0username\0access_token")
  </auth>
  ```
- This **access token must be the bearer token obtained from Keycloak**.
- If the token is expired, invalid, or not passed correctly, the server responds with:
  ```xml
  <failure xmlns="urn:ietf:params:xml:ns:xmpp-sasl"><not-authorized/></failure>
  ```

### Authorization Header
- A working session includes:
  ```
  Authorization: Bearer <access_token>
  ```

---

## ✅ Summary of Functional Python Script Flow

1. Prompt for username, password, recipient JID, and message.
2. Request Keycloak token using correct URL and headers.
3. Connect to BOSH and initiate XMPP session.
4. Authenticate via SASL using `PLAIN` and the bearer token.
5. Bind a resource and open a session.
6. Send an XMPP `<message>` stanza to the target JID.

---

## ❗ Troubleshooting Lessons

- Omitting `targetIdp=LDAP1` from the **query string** breaks login.
- Some 401 responses stem from headers not mimicking the browser.
- `not-authorized` on SASL auth usually means:
  - Token was not passed correctly
  - Wrong token format
  - Token expired

---