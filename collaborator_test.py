import getpass
import uuid
import base64
import xml.etree.ElementTree as ET
import requests

# === Configuration ===
BOSH_URL = "https://abpei-hub-app-north.albertahealthservices.ca:7443/http-bind/"
CLIENT_ID = "netboot"
TARGET_IDP = "LDAP1"
REALM = "EI"
KEYCLOAK_URL = f"https://abpei-hub-app-north.albertahealthservices.ca/auth/realms/{REALM}/protocol/openid-connect/token?targetIdp={TARGET_IDP}"

# === User Input ===
username = input("Username: ")
password = getpass.getpass("Password: ")
target_jid = input("Send messages to JID (e.g., user@agfa.com): ")
message_body = input("Enter message to send: ")

# === Step 1: Get access token from Keycloak ===
print("[*] Authenticating with Keycloak...")
try:
    token_resp = requests.post(KEYCLOAK_URL, data={
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": username,
        "password": password,
        "scope": "openid"
    })
    token_resp.raise_for_status()
    access_token = token_resp.json()["access_token"]
    print("[+] Got access token")
except requests.exceptions.HTTPError as e:
    if token_resp.status_code == 401:
        print("❌ Authentication failed - Invalid username/password")
    elif token_resp.status_code == 400:
        print("❌ Bad request - Check if targetIdp=LDAP1 is included in URL")
    else:
        print(f"❌ HTTP Error {token_resp.status_code}: {token_resp.text}")
    raise
except requests.exceptions.RequestException as e:
    print(f"❌ Network error: {e}")
    raise

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "text/xml; charset=UTF-8",
    "Origin": "https://abpei-hub-app-north.albertahealthservices.ca",
    "Referer": "https://abpei-hub-app-north.albertahealthservices.ca/",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/xml, application/xml, application/xhtml+xml, text/html;q=0.9, text/plain;q=0.8, text/css, image/*;q=0.5, */*;q=0.1",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin"
}

# === Step 2: Start BOSH Session ===
class RIDManager:
    def __init__(self):
        self.rid = int(uuid.uuid4().int % 1e10)
    
    def next_rid(self):
        self.rid += 1
        return self.rid

rid_manager = RIDManager()
rid = rid_manager.next_rid()
init_body = f"""
<body rid='{rid}' xmlns='http://jabber.org/protocol/httpbind' to='agfa.com' xml:lang='en' wait='60' hold='1' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>
"""
try:
    resp = requests.post(BOSH_URL, headers=headers, data=init_body.strip())
    resp.raise_for_status()
    tree = ET.fromstring(resp.text)
    sid = tree.attrib["sid"]
    print(f"[+] Connected, sid: {sid}")
except requests.exceptions.HTTPError as e:
    print(f"❌ BOSH connection failed: HTTP {resp.status_code}")
    print(f"Response: {resp.text}")
    raise
except ET.ParseError as e:
    print(f"❌ Invalid XML response from BOSH server: {e}")
    print(f"Response: {resp.text}")
    raise

# === Step 3: Pre-authenticated - Skip SASL (using JWT token like web client) ===
print("[+] Using JWT pre-authentication (no SASL required)")

# === Step 4: Resource binding ===
rid = rid_manager.next_rid()
bind_body = f"""
<body rid='{rid}' sid='{sid}' xmlns='http://jabber.org/protocol/httpbind'>
  <iq type='set' id='bind_1' xmlns='jabber:client'>
    <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
  </iq>
</body>
"""
bind_resp = requests.post(BOSH_URL, headers=headers, data=bind_body.strip())
bind_resp.raise_for_status()

print(f"[DEBUG] Bind response: {bind_resp.text}")
bind_tree = ET.fromstring(bind_resp.text)
jid_element = bind_tree.find('.//{urn:ietf:params:xml:ns:xmpp-bind}jid')

if jid_element is None:
    print("❌ Resource binding failed - no JID returned")
    print(f"Full response: {bind_resp.text}")
    raise Exception("Resource binding failed")

jid = jid_element.text
print(f"[+] Bound to JID: {jid}")

# === Step 5: Start session ===
rid = rid_manager.next_rid()
session_body = f"""
<body rid='{rid}' sid='{sid}' xmlns='http://jabber.org/protocol/httpbind'>
  <iq to='agfa.com' type='set' id='sess_1' xmlns='jabber:client'>
    <session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>
  </iq>
</body>
"""
requests.post(BOSH_URL, headers=headers, data=session_body.strip())

# === Step 6: Send message ===
rid = rid_manager.next_rid()
msg_body = f"""
<body rid='{rid}' sid='{sid}' xmlns='http://jabber.org/protocol/httpbind'>
  <message to='{target_jid}' type='chat' xmlns='jabber:client'>
    <body>{message_body}</body>
  </message>
</body>
"""
msg_resp = requests.post(BOSH_URL, headers=headers, data=msg_body.strip())
msg_resp.raise_for_status()
print("[+] Message sent.")
