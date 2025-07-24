import getpass
import uuid
import requests
import xml.etree.ElementTree as ET

# === Configuration ===
BOSH_URL = "https://abpei-hub-app-north.albertahealthservices.ca:7443/http-bind/"
CLIENT_ID = "netboot"
TARGET_IDP = "LDAP1"
REALM = "EI"
KEYCLOAK_URL = f"https://abpei-hub-app-north.albertahealthservices.ca/auth/realms/{REALM}/protocol/openid-connect/token?targetIdp={TARGET_IDP}"
WEB_CHAT_URL = "https://abpei-hub-app-north.albertahealthservices.ca/webchat"

class WebChatAuth:
    def __init__(self):
        self.session = requests.Session()
        self.rid_manager = RIDManager()
        self.sid = None
        self.jid = None
        self.jwt_token = None
    
    def authenticate_via_web_token(self, jwt_token):
        """Alternative authentication method using JWT token like the web client"""
        self.jwt_token = jwt_token
        
        # Set up headers to mimic web client
        self.session.headers.update({
            "Content-Type": "text/xml; charset=UTF-8",
            "Origin": "https://abpei-hub-app-north.albertahealthservices.ca",
            "Referer": f"https://abpei-hub-app-north.albertahealthservices.ca/webchat?token={jwt_token}",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/xml, application/xml, application/xhtml+xml, text/html;q=0.9, text/plain;q=0.8, text/css, image/*;q=0.5, */*;q=0.1",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin"
        })
        
        # Start BOSH session (pre-authenticated)
        rid = self.rid_manager.next_rid()
        init_body = f"""
        <body rid='{rid}' xmlns='http://jabber.org/protocol/httpbind' to='agfa.com' xml:lang='en' wait='60' hold='1' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>
        """
        
        resp = self.session.post(BOSH_URL, data=init_body.strip())
        resp.raise_for_status()
        
        tree = ET.fromstring(resp.text)
        self.sid = tree.attrib["sid"]
        print(f"[+] Web-style BOSH connected, sid: {self.sid}")
        
        # No SASL authentication needed - pre-authenticated via JWT
        return True
    
    def bind_resource_and_session(self):
        """Bind resource and establish session"""
        if not self.sid:
            raise Exception("Not connected to BOSH")
        
        # Resource binding
        rid = self.rid_manager.next_rid()
        bind_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
          <iq type='set' id='bind_1' xmlns='jabber:client'>
            <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
          </iq>
        </body>
        """
        
        bind_resp = self.session.post(BOSH_URL, data=bind_body.strip())
        bind_resp.raise_for_status()
        
        self.jid = ET.fromstring(bind_resp.text).find('.//{urn:ietf:params:xml:ns:xmpp-bind}jid').text
        print(f"[+] Bound to JID: {self.jid}")
        
        # Start session
        rid = self.rid_manager.next_rid()
        session_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
          <iq to='agfa.com' type='set' id='sess_1' xmlns='jabber:client'>
            <session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>
          </iq>
        </body>
        """
        
        self.session.post(BOSH_URL, data=session_body.strip())
        print("[+] Session established")
    
    def send_message(self, target_jid, message_body):
        """Send a message to target JID"""
        if not self.sid:
            raise Exception("Not connected")
        
        rid = self.rid_manager.next_rid()
        msg_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
          <message to='{target_jid}' type='chat' xmlns='jabber:client'>
            <body>{message_body}</body>
          </message>
        </body>
        """
        
        msg_resp = self.session.post(BOSH_URL, data=msg_body.strip())
        msg_resp.raise_for_status()
        print("[+] Message sent via web-style authentication")

class RIDManager:
    def __init__(self):
        self.rid = int(uuid.uuid4().int % 1e10)
    
    def next_rid(self):
        self.rid += 1
        return self.rid

def main():
    print("=== Web-Client Style XMPP Authentication ===")
    jwt_token = input("Enter JWT token (from web client URL): ")
    target_jid = input("Send messages to JID (e.g., user@agfa.com): ")
    message_body = input("Enter message to send: ")
    
    try:
        client = WebChatAuth()
        
        # Authenticate using JWT token (web-client style)
        client.authenticate_via_web_token(jwt_token)
        
        # Bind resource and establish session
        client.bind_resource_and_session()
        
        # Send message
        client.send_message(target_jid, message_body)
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()