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
            },
            "filter_self_messages": True,
            "filter_bot_messages": True,
            "bot_indicators": ['🤖', 'auto-reply', 'automated', 'bot', 'testing autoreply']
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
        
        # Extract and debug resource information
        if '/' in self.jid:
            bare_jid, resource = self.jid.split('/', 1)
            print(f"[DEBUG] Bare JID: {bare_jid}")
            print(f"[DEBUG] Our Resource: {resource}")
            print("[DEBUG] Other clients on same bare JID will compete for messages")
        else:
            print("[DEBUG] Warning: No resource in JID - this is unusual")

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
        
        # Set high priority presence to receive messages (fix for multi-client conflicts)
        self.set_high_priority_presence()

    def set_high_priority_presence(self):
        """Set high priority presence to win message routing vs other clients"""
        if not self.sid:
            return
        
        rid = self.rid_manager.next_rid()
        # Set priority to +10 to beat most web clients (usually 0-5)
        presence_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
          <presence xmlns='jabber:client'>
            <priority>10</priority>
            <status>Auto-reply bot active</status>
            <show>chat</show>
          </presence>
        </body>
        """
        
        print("[DEBUG] Setting high priority presence to win message routing...")
        try:
            presence_resp = self.session.post(BOSH_URL, data=presence_body.strip())
            presence_resp.raise_for_status()
            print("[+] High priority presence set (priority: 10)")
            print(f"[DEBUG] Our JID: {self.jid}")
            print("[DEBUG] This should make us the preferred client for incoming messages")
        except Exception as e:
            print(f"❌ Failed to set presence: {e}")

    def is_self_message(self, from_jid):
        """Check if a message is from the bot itself to prevent infinite loops"""
        if not self.jid:
            return False
        
        # Compare full JIDs (exact match)
        if from_jid == self.jid:
            return True
        
        # Compare bare JIDs (same user, different resource)
        our_bare_jid = self.jid.split('/')[0] if '/' in self.jid else self.jid
        sender_bare_jid = from_jid.split('/')[0] if '/' in from_jid else from_jid
        
        # For now, filter all messages from same bare JID to be safe
        # This prevents loops from any resource of the same user
        return our_bare_jid == sender_bare_jid

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
            print(f"[DEBUG] Parsing XML: {xml_response}")
            root = ET.fromstring(xml_response)
            
            # Debug: Print all child elements
            for child in root:
                print(f"[DEBUG] Found child element: {child.tag} with attribs: {child.attrib}")
            
            # Look for message stanzas in the BOSH body
            # Try multiple XPath approaches
            message_elements = []
            
            # Approach 1: Direct children
            for child in root:
                if child.tag.endswith('message'):  # Handle namespaced tags
                    message_elements.append(child)
                    print(f"[DEBUG] Found message element via direct child: {child.tag}")
            
            # Approach 2: Find all message elements regardless of namespace
            for message in root.iter():
                if message.tag.endswith('message'):
                    if message not in message_elements:
                        message_elements.append(message)
                        print(f"[DEBUG] Found message element via iter: {message.tag}")
            
            print(f"[DEBUG] Total message elements found: {len(message_elements)}")
            
            for message in message_elements:
                msg_type = message.get('type', '')
                print(f"[DEBUG] Processing message with type: {msg_type}")
                
                if msg_type == 'chat':
                    from_jid = message.get('from', '')
                    to_jid = message.get('to', '')
                    msg_id = message.get('id', '')
                    
                    print(f"[DEBUG] Message details - From: {from_jid}, To: {to_jid}, ID: {msg_id}")
                    
                    # Extract message body - try multiple approaches
                    body_text = ''
                    
                    # Try direct child
                    for child in message:
                        if child.tag.endswith('body'):
                            body_text = child.text or ''
                            print(f"[DEBUG] Found body via direct child: '{body_text}'")
                            break
                    
                    # Try iterating all descendants
                    if not body_text:
                        for elem in message.iter():
                            if elem.tag.endswith('body'):
                                body_text = elem.text or ''
                                print(f"[DEBUG] Found body via iter: '{body_text}'")
                                break
                    
                    # Check if receipt is requested
                    receipt_requested = False
                    for elem in message.iter():
                        if 'receipts' in elem.tag and elem.tag.endswith('request'):
                            receipt_requested = True
                            print(f"[DEBUG] Receipt requested")
                            break
                    
                    if body_text and from_jid:
                        # CRITICAL: Filter out self-messages to prevent infinite loops
                        if self.is_self_message(from_jid):
                            print(f"[DEBUG] *** FILTERING SELF-MESSAGE ***")
                            print(f"[DEBUG] Message from: {from_jid}")
                            print(f"[DEBUG] Our JID: {self.jid}")
                            print(f"[DEBUG] Body: '{body_text}'")
                            print(f"[DEBUG] Self-message ignored to prevent infinite loop")
                            continue
                        
                        print(f"[DEBUG] Message from external sender - processing...")
                        
                        if not msg_id:
                            msg_id = f"auto_generated_{int(time.time() * 1000)}"
                        
                        if msg_id not in self.processed_messages:
                            message_data = {
                                'from': from_jid,
                                'to': to_jid,
                                'body': body_text,
                                'id': msg_id,
                                'receipt_requested': receipt_requested,
                                'timestamp': datetime.now()
                            }
                            messages.append(message_data)
                            self.processed_messages.add(msg_id)
                            print(f"[DEBUG] Added external message to processing queue: {message_data}")
                        else:
                            print(f"[DEBUG] Message {msg_id} already processed, skipping")
                    else:
                        print(f"[DEBUG] Skipping message - body_text: '{body_text}', from_jid: '{from_jid}'")
                        
        except ET.ParseError as e:
            print(f"❌ XML parsing error: {e}")
            print(f"[DEBUG] Raw XML causing error: {xml_response}")
        except Exception as e:
            print(f"❌ Message parsing error: {e}")
            print(f"[DEBUG] Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
        
        return messages

    def generate_auto_reply(self, incoming_message):
        """Generate auto-reply based on incoming message content"""
        if not self.auto_reply_config["enabled"]:
            print("[DEBUG] Auto-reply disabled")
            return None
        
        # Additional safety check to prevent loops
        if self.is_self_message(incoming_message['from']):
            print("[DEBUG] Skipping auto-reply for self-message (double-check)")
            return None
        
        body = incoming_message['body'].lower().strip()
        
        # Check if this looks like a bot message to prevent reply loops
        if self.auto_reply_config.get("filter_bot_messages", True):
            bot_indicators = self.auto_reply_config.get("bot_indicators", [])
            if any(indicator in body for indicator in bot_indicators):
                print(f"[DEBUG] Message contains bot indicators: {body}")
                print("[DEBUG] Skipping auto-reply to prevent bot-to-bot loops")
                return None
        
        print(f"[DEBUG] Generating auto-reply for message: '{body}'")
        
        # Check for custom replies
        for trigger, reply in self.auto_reply_config["custom_replies"].items():
            if trigger in body:
                print(f"[DEBUG] Matched custom trigger: '{trigger}' -> '{reply}'")
                return reply
        
        # Default reply
        print(f"[DEBUG] Using default reply: '{self.auto_reply_config['default_reply']}'")
        return self.auto_reply_config["default_reply"]

    def poll_messages(self):
        """Poll for incoming messages via BOSH with proper long-polling"""
        if not self.sid:
            return []
        
        rid = self.rid_manager.next_rid()
        # Proper BOSH long-polling with wait and hold attributes
        poll_body = f"""<body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind' wait='60' hold='1'/>"""
        
        print(f"[DEBUG] BOSH Poll Request (RID: {rid}): {poll_body}")
        
        try:
            # Use long timeout for BOSH long-polling (60+ seconds)
            resp = self.session.post(BOSH_URL, data=poll_body.strip(), timeout=65)
            resp.raise_for_status()
            
            print(f"[DEBUG] BOSH Poll Response: {resp.text}")
            
            # Check for ack attribute in response
            try:
                root = ET.fromstring(resp.text)
                ack_value = root.get('ack')
                if ack_value:
                    print(f"[DEBUG] Server ACK: {ack_value}")
            except ET.ParseError:
                pass
            
            # Parse and return any messages
            messages = self.parse_incoming_messages(resp.text)
            if messages:
                print(f"[DEBUG] Found {len(messages)} messages in response")
            else:
                print("[DEBUG] Empty response - no messages")
            
            return messages
            
        except requests.exceptions.Timeout:
            print("[DEBUG] BOSH poll timeout (normal for long-polling)")
            return []
        except Exception as e:
            print(f"❌ Polling error: {e}")
            print(f"[DEBUG] Error details: {type(e).__name__}")
            return []

    def message_loop(self):
        """Main message receiving and auto-reply loop"""
        print("[+] Starting message loop with enhanced debugging...")
        print(f"[DEBUG] Bot JID: {self.jid}")
        print(f"[DEBUG] Session ID: {self.sid}")
        print("[DEBUG] Starting continuous BOSH polling...")
        
        self.running = True
        poll_count = 0
        
        while self.running:
            try:
                poll_count += 1
                print(f"\n[DEBUG] === Poll Cycle #{poll_count} ===")
                
                # Poll for messages
                messages = self.poll_messages()
                
                if messages:
                    print(f"[DEBUG] Processing {len(messages)} messages...")
                    
                for message in messages:
                    print(f"\n📨 *** NEW MESSAGE RECEIVED ***")
                    print(f"From: {message['from']}")
                    print(f"To: {message['to']}")
                    print(f"Body: {message['body']}")
                    print(f"ID: {message['id']}")
                    print(f"Receipt requested: {message['receipt_requested']}")
                    print(f"Timestamp: {message['timestamp']}")
                    
                    # Send receipt if requested
                    if message['receipt_requested']:
                        self.send_receipt(message['from'], message['id'])
                        print(f"✅ Sent receipt for message {message['id']}")
                    
                    # Generate and send auto-reply
                    reply = self.generate_auto_reply(message)
                    if reply:
                        print(f"[DEBUG] Generated auto-reply: '{reply}'")
                        # Wait configured delay before replying
                        print(f"[DEBUG] Waiting {self.auto_reply_config['delay_seconds']} seconds before reply...")
                        time.sleep(self.auto_reply_config["delay_seconds"])
                        
                        if self.send_message(message['from'], reply):
                            print(f"🤖 Auto-replied to {message['from']}: {reply}")
                        else:
                            print(f"❌ Failed to send auto-reply to {message['from']}")
                    else:
                        print("[DEBUG] No auto-reply configured for this message")
                
                if not messages:
                    print(f"[DEBUG] Poll cycle {poll_count} complete - no messages")
                
                # No sleep between polls - BOSH handles timing with wait/hold
                
            except KeyboardInterrupt:
                print("\n[*] Stopping message loop...")
                self.running = False
                break
            except Exception as e:
                print(f"❌ Message loop error: {e}")
                print(f"[DEBUG] Exception in poll cycle {poll_count}")
                import traceback
                traceback.print_exc()
                print("[DEBUG] Waiting 5 seconds before retry...")
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
        print("[+] High priority presence set - should receive messages over other clients")
        print("[+] Press Ctrl+C to stop")
        
        # Optional: Send test message to self to verify routing
        test_choice = input("Send test message to yourself to test routing? (y/n): ").lower()
        if test_choice == 'y':
            bare_jid = bot.jid.split('/')[0] if '/' in bot.jid else bot.jid
            if bot.send_message(bare_jid, "🤖 Test message from auto-reply bot - checking message routing"):
                print("[+] Test message sent - watch to see which client receives it!")
            else:
                print("❌ Failed to send test message")
        
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