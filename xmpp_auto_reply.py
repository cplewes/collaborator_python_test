import getpass
import uuid
import base64
import requests
import xml.etree.ElementTree as ET
import time
import threading
import json
from datetime import datetime

# === Configuration ===
BOSH_URL = "https://abpei-hub-app-north.albertahealthservices.ca:7443/http-bind/"
CLIENT_ID = "netboot"
TARGET_IDP = "LDAP1"
REALM = "EI"
KEYCLOAK_URL = f"https://abpei-hub-app-north.albertahealthservices.ca/auth/realms/{REALM}/protocol/openid-connect/token?targetIdp={TARGET_IDP}"

class RIDManager:
    def __init__(self):
        self.rid = int(uuid.uuid4().int % 1e10)
    
    def next_rid(self):
        self.rid += 1
        return self.rid

class XMPPAutoReplyBot:
    def __init__(self):
        self.session = requests.Session()
        self.rid_manager = RIDManager()
        self.sid = None
        self.jid = None
        self.access_token = None
        self.running = False
        self.auto_reply_config = {
            "enabled": True,
            "delay_seconds": 2,
            "default_reply": "This is an automated response. I'll get back to you soon!",
            "custom_replies": {
                "hello": "Hello! How can I help you?",
                "help": "I'm currently away but will respond as soon as possible.",
                "status": "I'm currently online via auto-reply bot."
            }
        }
        self.processed_messages = set()  # Track processed message IDs
    
    def authenticate(self, username, password):
        """Authenticate with Keycloak and establish BOSH session"""
        print("[*] Authenticating with Keycloak...")
        try:
            token_resp = self.session.post(KEYCLOAK_URL, data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "username": username,
                "password": password,
                "scope": "openid"
            })
            token_resp.raise_for_status()
            self.access_token = token_resp.json()["access_token"]
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

        # Set up headers
        self.session.headers.update({
            "Authorization": f"Bearer {self.access_token}",
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
        })

        # Start BOSH session
        rid = self.rid_manager.next_rid()
        init_body = f"""
        <body rid='{rid}' xmlns='http://jabber.org/protocol/httpbind' to='agfa.com' xml:lang='en' wait='60' hold='1' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>
        """
        
        try:
            resp = self.session.post(BOSH_URL, data=init_body.strip())
            resp.raise_for_status()
            tree = ET.fromstring(resp.text)
            self.sid = tree.attrib["sid"]
            print(f"[+] BOSH connected, sid: {self.sid}")
        except Exception as e:
            print(f"❌ BOSH connection failed: {e}")
            raise

        # SASL Authentication
        rid = self.rid_manager.next_rid()
        auth_str = f"\x00{username}\x00{self.access_token}"
        auth_b64 = base64.b64encode(auth_str.encode()).decode()
        auth_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
          <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth_b64}</auth>
        </body>
        """
        
        try:
            auth_resp = self.session.post(BOSH_URL, data=auth_body.strip())
            auth_resp.raise_for_status()
            
            if "<success" not in auth_resp.text:
                raise Exception("SASL Authentication failed")
            print("[+] SASL Authentication successful")
        except Exception as e:
            print(f"❌ SASL Authentication failed: {e}")
            raise

        # Restart stream
        rid = self.rid_manager.next_rid()
        restart_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind' to='agfa.com' xml:lang='en' xmpp:restart='true' xmlns:xmpp='urn:xmpp:xbosh'/>
        """
        self.session.post(BOSH_URL, data=restart_body.strip())

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
        
        bind_tree = ET.fromstring(bind_resp.text)
        jid_element = bind_tree.find('.//{urn:ietf:params:xml:ns:xmpp-bind}jid')
        
        if jid_element is None:
            raise Exception("Resource binding failed")
        
        self.jid = jid_element.text
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
        print("[+] XMPP session established")

    def send_message(self, to_jid, message_body, include_receipt=True):
        """Send a message to specified JID"""
        if not self.sid:
            raise Exception("Not connected")
        
        rid = self.rid_manager.next_rid()
        receipt_xml = '<request xmlns="urn:xmpp:receipts"/>' if include_receipt else ''
        
        msg_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
          <message to='{to_jid}' type='chat' xmlns='jabber:client'>
            <body>{message_body}</body>
            {receipt_xml}
            <active xmlns='http://jabber.org/protocol/chatstates'/>
          </message>
        </body>
        """
        
        try:
            msg_resp = self.session.post(BOSH_URL, data=msg_body.strip())
            msg_resp.raise_for_status()
            return True
        except Exception as e:
            print(f"❌ Failed to send message: {e}")
            return False

    def send_receipt(self, to_jid, message_id):
        """Send message receipt confirmation"""
        if not self.sid or not message_id:
            return
            
        rid = self.rid_manager.next_rid()
        receipt_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
          <message to='{to_jid}' xmlns='jabber:client'>
            <received xmlns='urn:xmpp:receipts' id='{message_id}'/>
          </message>
        </body>
        """
        
        try:
            self.session.post(BOSH_URL, data=receipt_body.strip())
        except Exception as e:
            print(f"❌ Failed to send receipt: {e}")

    def parse_incoming_messages(self, xml_response):
        """Parse incoming XMPP messages from BOSH response"""
        messages = []
        try:
            root = ET.fromstring(xml_response)
            # Find all message stanzas
            for message in root.findall('.//{jabber:client}message'):
                msg_type = message.get('type', '')
                if msg_type == 'chat':
                    from_jid = message.get('from', '')
                    to_jid = message.get('to', '')
                    msg_id = message.get('id', '')
                    
                    # Extract message body
                    body_elem = message.find('.//{jabber:client}body')
                    body_text = body_elem.text if body_elem is not None else ''
                    
                    # Check if receipt is requested
                    receipt_requested = message.find('.//{urn:xmpp:receipts}request') is not None
                    
                    if body_text and from_jid and msg_id not in self.processed_messages:
                        messages.append({
                            'from': from_jid,
                            'to': to_jid,
                            'body': body_text,
                            'id': msg_id,
                            'receipt_requested': receipt_requested,
                            'timestamp': datetime.now()
                        })
                        self.processed_messages.add(msg_id)
        except ET.ParseError as e:
            print(f"❌ XML parsing error: {e}")
        except Exception as e:
            print(f"❌ Message parsing error: {e}")
        
        return messages

    def generate_auto_reply(self, incoming_message):
        """Generate auto-reply based on incoming message content"""
        if not self.auto_reply_config["enabled"]:
            return None
        
        body = incoming_message['body'].lower().strip()
        
        # Check for custom replies
        for trigger, reply in self.auto_reply_config["custom_replies"].items():
            if trigger in body:
                return reply
        
        # Default reply
        return self.auto_reply_config["default_reply"]

    def poll_messages(self):
        """Poll for incoming messages via BOSH"""
        if not self.sid:
            return []
        
        rid = self.rid_manager.next_rid()
        poll_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'/>
        """
        
        try:
            resp = self.session.post(BOSH_URL, data=poll_body.strip(), timeout=30)
            resp.raise_for_status()
            return self.parse_incoming_messages(resp.text)
        except requests.exceptions.Timeout:
            # Timeout is normal for long polling
            return []
        except Exception as e:
            print(f"❌ Polling error: {e}")
            return []

    def message_loop(self):
        """Main message receiving and auto-reply loop"""
        print("[+] Starting message loop...")
        self.running = True
        
        while self.running:
            try:
                # Poll for messages
                messages = self.poll_messages()
                
                for message in messages:
                    print(f"\n📨 Received message from {message['from']}: {message['body']}")
                    
                    # Send receipt if requested
                    if message['receipt_requested']:
                        self.send_receipt(message['from'], message['id'])
                        print(f"✅ Sent receipt for message {message['id']}")
                    
                    # Generate and send auto-reply
                    reply = self.generate_auto_reply(message)
                    if reply:
                        # Wait configured delay before replying
                        time.sleep(self.auto_reply_config["delay_seconds"])
                        
                        if self.send_message(message['from'], reply):
                            print(f"🤖 Auto-replied to {message['from']}: {reply}")
                        else:
                            print(f"❌ Failed to send auto-reply to {message['from']}")
                
                # Brief pause between polling cycles
                time.sleep(1)
                
            except KeyboardInterrupt:
                print("\n[*] Stopping message loop...")
                self.running = False
                break
            except Exception as e:
                print(f"❌ Message loop error: {e}")
                time.sleep(5)  # Wait before retrying

    def stop(self):
        """Stop the message loop"""
        self.running = False

    def configure_auto_reply(self, config):
        """Update auto-reply configuration"""
        self.auto_reply_config.update(config)
        print(f"[+] Auto-reply configuration updated: {json.dumps(self.auto_reply_config, indent=2)}")

def main():
    print("=== XMPP Auto-Reply Bot ===")
    
    # Get credentials
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    
    # Create and authenticate bot
    bot = XMPPAutoReplyBot()
    
    try:
        bot.authenticate(username, password)
        
        # Configure auto-reply (optional)
        config_choice = input("Configure custom auto-replies? (y/n): ").lower()
        if config_choice == 'y':
            custom_config = {
                "delay_seconds": int(input("Reply delay in seconds (default 2): ") or "2"),
                "default_reply": input("Default auto-reply message: ") or bot.auto_reply_config["default_reply"]
            }
            bot.configure_auto_reply(custom_config)
        
        print(f"\n[+] Bot is ready! Monitoring messages for {bot.jid}")
        print("[+] Press Ctrl+C to stop")
        
        # Start message loop
        bot.message_loop()
        
    except KeyboardInterrupt:
        print("\n[*] Shutting down bot...")
    except Exception as e:
        print(f"❌ Bot error: {e}")
    finally:
        bot.stop()

if __name__ == "__main__":
    main()