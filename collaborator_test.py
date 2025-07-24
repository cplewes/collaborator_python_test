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

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "text/xml; charset=utf-8"
}

# === Step 2: Start BOSH Session ===
rid = int(uuid.uuid4().int % 1e10)
init_body = f"""
<body rid='{rid}' xmlns='http://jabber.org/protocol/httpbind' to='agfa.com' xml:lang='en' wait='60' hold='1' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>
"""
resp = requests.post(BOSH_URL, headers=headers, data=init_body.strip())
resp.raise_for_status()
tree = ET.fromstring(resp.text)
sid = tree.attrib["sid"]
print(f"[+] Connected, sid: {sid}")

# === Step 3: SASL Auth ===
rid += 1
auth_str = f"\x00{username}\x00{password}"
auth_b64 = base64.b64encode(auth_str.encode()).decode()
auth_body = f"""
<body rid='{rid}' sid='{sid}' xmlns='http://jabber.org/protocol/httpbind'>
  <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth_b64}</auth>
</body>
"""
auth_resp = requests.post(BOSH_URL, headers=headers, data=auth_body.strip())
auth_resp.raise_for_status()

if "<success" not in auth_resp.text:
    print(auth_resp.text)
    raise Exception("❌ Authentication failed")
print("[+] Authenticated")

# === Step 4: Restart stream ===
rid += 1
restart_body = f"""
<body rid='{rid}' sid='{sid}' xmlns='http://jabber.org/protocol/httpbind' to='agfa.com' xml:lang='en' xmpp:restart='true' xmlns:xmpp='urn:xmpp:xbosh'/>
"""
requests.post(BOSH_URL, headers=headers, data=restart_body.strip())

# === Step 5: Resource binding ===
rid += 1
bind_body = f"""
<body rid='{rid}' sid='{sid}' xmlns='http://jabber.org/protocol/httpbind'>
  <iq type='set' id='bind_1' xmlns='jabber:client'>
    <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
  </iq>
</body>
"""
bind_resp = requests.post(BOSH_URL, headers=headers, data=bind_body.strip())
bind_resp.raise_for_status()
jid = ET.fromstring(bind_resp.text).find('.//{urn:ietf:params:xml:ns:xmpp-bind}jid').text
print(f"[+] Bound to JID: {jid}")

# === Step 6: Start session ===
rid += 1
session_body = f"""
<body rid='{rid}' sid='{sid}' xmlns='http://jabber.org/protocol/httpbind'>
  <iq to='agfa.com' type='set' id='sess_1' xmlns='jabber:client'>
    <session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>
  </iq>
</body>
"""
requests.post(BOSH_URL, headers=headers, data=session_body.strip())

# === Step 7: Send message ===
rid += 1
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
