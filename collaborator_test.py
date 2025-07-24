import getpass
import uuid
import base64
import xml.etree.ElementTree as ET
import requests
import time

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
resp = requests.post(KEYCLOAK_URL, data={
    "grant_type": "password",
    "client_id": CLIENT_ID,
    "username": username,
    "password": password,
    "scope": "openid"
})
resp.raise_for_status()
access_token = resp.json()["access_token"]
print("[+] Got access token")

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "text/xml; charset=utf-8"
}
# === Step 2: Initiate BOSH Session ===
rid = int(time.time() * 1000)
body = f"""<body rid='{rid}'
  xmlns='http://jabber.org/protocol/httpbind'
  to='agfa.com'
  xml:lang='en'
  wait='60'
  hold='1'
  ver='1.6'
  xmpp:version='1.0'
  xmlns:xmpp='urn:xmpp:xbosh'/>"""

resp = requests.post(BOSH_URL, headers=headers, data=body)
resp.raise_for_status()
xml = ET.fromstring(resp.text)
sid = xml.attrib["sid"]
print(f"[+] Connected, sid: {sid}")

# === Step 3: SASL PLAIN Authentication ===
authzid = ""
authcid = username
passwd = password
msg = f"{authzid}\x00{authcid}\x00{passwd}"
auth_b64 = base64.b64encode(msg.encode()).decode()

rid += 1
body = f"""<body rid='{rid}' sid='{sid}'
  xmlns='http://jabber.org/protocol/httpbind'>
  <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth_b64}</auth>
</body>"""

resp = requests.post(BOSH_URL, headers=headers, data=body)
resp.raise_for_status()
if "<success" not in resp.text:
    print(resp.text)
    raise Exception("❌ Authentication failed")
print("[+] Authenticated")

# === Step 4: Restart stream after SASL ===
rid += 1
body = f"""<body rid='{rid}' sid='{sid}'
  xmlns='http://jabber.org/protocol/httpbind'
  to='agfa.com'
  xml:lang='en'
  xmpp:restart='true'
  xmlns:xmpp='urn:xmpp:xbosh'/>"""
resp = requests.post(BOSH_URL, headers=headers, data=body)
resp.raise_for_status()

# === Step 5: Resource Bind ===
rid += 1
body = f"""<body rid='{rid}' sid='{sid}'
  xmlns='http://jabber.org/protocol/httpbind'>
  <iq type='set' id='bind_1'
    xmlns='jabber:client'>
    <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
  </iq>
</body>"""
resp = requests.post(BOSH_URL, headers=headers, data=body)
resp.raise_for_status()
jid = ET.fromstring(resp.text).find('.//{urn:ietf:params:xml:ns:xmpp-bind}jid').text
print(f"[+] Bound JID: {jid}")

# === Step 6: Establish Session ===
rid += 1
body = f"""<body rid='{rid}' sid='{sid}'
  xmlns='http://jabber.org/protocol/httpbind'>
  <iq type='set' id='sess_1'
    xmlns='jabber:client'>
    <session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>
  </iq>
</body>"""
resp = requests.post(BOSH_URL, headers=headers, data=body)
resp.raise_for_status()

# === Step 7: Send Message ===
rid += 1
msg_id = str(uuid.uuid4())
body = f"""<body rid='{rid}' sid='{sid}'
  xmlns='http://jabber.org/protocol/httpbind'>
  <message to='{target_jid}' type='chat' id='{msg_id}'
    xmlns='jabber:client'>
    <body>{message_body}</body>
  </message>
</body>"""
resp = requests.post(BOSH_URL, headers=headers, data=body)
resp.raise_for_status()
print(f"[+] Message sent to {target_jid}")
