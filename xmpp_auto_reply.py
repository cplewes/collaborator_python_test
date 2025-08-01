import getpass
import uuid
import base64
import requests
import xml.etree.ElementTree as ET
import time
import threading
import json
import queue
import re
import urllib.parse
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
        
        # Threading infrastructure for concurrent processing
        self.message_queue = queue.Queue()
        self.polling_thread = None
        self.processor_thread = None
        self.console_thread = None
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

    def update_presence(self, show_state=None, status_message=None, priority=None):
        """Update presence with custom show state and status message"""
        if not self.sid:
            print("❌ Cannot update presence - not connected")
            return False
        
        # Use current values as defaults
        current_priority = priority if priority is not None else 10
        
        rid = self.rid_manager.next_rid()
        
        # Build presence XML dynamically
        presence_elements = []
        
        if priority is not None:
            presence_elements.append(f"<priority>{priority}</priority>")
        else:
            presence_elements.append(f"<priority>{current_priority}</priority>")
        
        if show_state:
            presence_elements.append(f"<show>{show_state}</show>")
        
        if status_message:
            presence_elements.append(f"<status>{status_message}</status>")
        
        presence_content = "\n    ".join(presence_elements)
        
        presence_body = f"""
        <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
          <presence xmlns='jabber:client'>
            {presence_content}
          </presence>
        </body>
        """
        
        print(f"[DEBUG] Updating presence...")
        print(f"[DEBUG] Show: {show_state}")
        print(f"[DEBUG] Status: {status_message}")
        print(f"[DEBUG] Priority: {current_priority}")
        
        try:
            presence_resp = self.session.post(BOSH_URL, data=presence_body.strip())
            presence_resp.raise_for_status()
            print("[+] Presence updated successfully")
            print(f"[DEBUG] Server response: {presence_resp.text}")
            return True
        except Exception as e:
            print(f"❌ Failed to update presence: {e}")
            return False

    def test_status_injection(self):
        """Test various status message payloads for security research"""
        print("\n🧪 *** STATUS INJECTION TESTING ***")
        print("Testing various payloads to investigate web UI rendering...")
        
        test_payloads = [
            # Basic tests
            ("text", "🤖 Basic Bot Status"),
            ("emoji", "🟢🔥⚡ Emoji Test ⚠️💀🚨"),
            
            # HTML tests
            ("html_bold", "<b>Bold Bot Status</b>"),
            ("html_italic", "<i>Italic Bot Status</i>"),
            ("html_span", "<span style='color:red'>Red Bot Status</span>"),
            
            # Event handler tests
            ("onclick", "<span onclick='alert(\"XSS Test\")'>Click Me Bot</span>"),
            ("onmouseover", "<span onmouseover='console.log(\"Hover Test\")'>Hover Bot</span>"),
            
            # Script injection tests
            ("script", "<script>console.log('Script Test')</script>Bot"),
            ("script_alert", "<script>alert('XSS Alert')</script>"),
            
            # CSS injection tests
            ("css_style", "<style>body{background-color:red!important}</style>Bot"),
            ("css_hide", "<style>.user-list{display:none!important}</style>"),
            
            # Advanced tests
            ("iframe", "<iframe src='javascript:alert(\"iframe\")'></iframe>Bot"),
            ("img_onerror", "<img src=x onerror=alert('img_error')>Bot"),
            ("svg", "<svg onload=alert('svg_load')></svg>Bot"),
            
            # Unicode escape tests
            ("unicode", "\\u003cscript\\u003ealert('unicode')\\u003c/script\\u003e"),
        ]
        
        results = []
        
        for test_name, payload in test_payloads:
            print(f"\n[TEST] {test_name}: {payload}")
            
            success = self.update_presence(show_state="online", status_message=payload)
            
            if success:
                print(f"✅ Payload accepted by server")
                user_input = input(f"Check web UI. Does '{test_name}' render as HTML/JS? (y/n/skip): ").lower()
                
                if user_input == 'y':
                    results.append((test_name, payload, "VULNERABLE - Renders as HTML/JS"))
                    print("🚨 POTENTIAL VULNERABILITY DETECTED!")
                elif user_input == 'n':
                    results.append((test_name, payload, "Safe - Rendered as text"))
                else:
                    results.append((test_name, payload, "Skipped"))
                    
                # Brief pause between tests
                time.sleep(1)
            else:
                results.append((test_name, payload, "Server rejected"))
                print(f"❌ Server rejected payload")
        
        # Summary report
        print("\n📊 *** INJECTION TEST RESULTS ***")
        for test_name, payload, result in results:
            print(f"{test_name}: {result}")
            if "VULNERABLE" in result:
                print(f"  Payload: {payload}")
        
        return results

    def detect_study_share_urls(self, message_body):
        """Detect study share URLs in message body"""
        if not message_body:
            return []
        
        # Regex pattern to match https://share.study.link URLs
        pattern = r'https://share\.study\.link[^\s]*'
        urls = re.findall(pattern, message_body, re.IGNORECASE)
        
        print(f"[DEBUG] Found {len(urls)} study share URLs in message")
        for url in urls:
            print(f"[DEBUG] Study URL: {url}")
        
        return urls

    def parse_study_share_url(self, url):
        """Parse study share URL and extract metadata"""
        try:
            # Parse the URL
            parsed = urllib.parse.urlparse(url)
            
            if not parsed.netloc.lower() == 'share.study.link':
                print(f"[DEBUG] Not a valid study share URL: {url}")
                return None
            
            # Parse query parameters
            params = urllib.parse.parse_qs(parsed.query)
            
            study_info = {}
            
            # Extract and decode studyUID (Base64)
            if 'studyUID' in params:
                try:
                    study_uid_b64 = params['studyUID'][0]
                    study_info['studyUID'] = base64.b64decode(study_uid_b64).decode('utf-8')
                    print(f"[DEBUG] Decoded studyUID: {study_info['studyUID']}")
                except Exception as e:
                    print(f"[DEBUG] Failed to decode studyUID: {e}")
                    study_info['studyUID'] = study_uid_b64  # Keep encoded if decode fails
            
            # Extract and decode patientId (Base64)
            if 'patientId' in params:
                try:
                    patient_id_b64 = params['patientId'][0]
                    study_info['patientId'] = base64.b64decode(patient_id_b64).decode('utf-8')
                    print(f"[DEBUG] Decoded patientId: {study_info['patientId']}")
                except Exception as e:
                    print(f"[DEBUG] Failed to decode patientId: {e}")
                    study_info['patientId'] = patient_id_b64  # Keep encoded if decode fails
            
            # Extract URL-encoded fields
            if 'issuer' in params:
                study_info['issuer'] = urllib.parse.unquote(params['issuer'][0])
                print(f"[DEBUG] Decoded issuer: {study_info['issuer']}")
            
            if 'procedure' in params:
                study_info['procedure'] = urllib.parse.unquote(params['procedure'][0])
                print(f"[DEBUG] Decoded procedure: {study_info['procedure']}")
            
            if 'id' in params:
                study_info['id'] = urllib.parse.unquote(params['id'][0])
                print(f"[DEBUG] Decoded id: {study_info['id']}")
            
            # Add raw URL for reference
            study_info['raw_url'] = url
            
            return study_info
            
        except Exception as e:
            print(f"❌ Failed to parse study share URL: {e}")
            print(f"[DEBUG] URL: {url}")
            return None

    def process_study_share(self, from_jid, study_info):
        """Process a detected study share"""
        print(f"\n🏥 *** STUDY SHARED DETECTED ***")
        print(f"Shared by: {from_jid}")
        print(f"Timestamp: {datetime.now()}")
        
        # Display extracted information
        print(f"\n📋 Study Information:")
        for key, value in study_info.items():
            if key != 'raw_url':  # Don't repeat the full URL
                print(f"  {key}: {value}")
        
        print(f"\n🔗 Raw URL: {study_info.get('raw_url', 'N/A')}")
        
        # Log to a structured format for potential future processing
        study_event = {
            'timestamp': datetime.now().isoformat(),
            'from_jid': from_jid,
            'study_info': study_info,
            'event_type': 'study_shared'
        }
        
        # Could be extended to save to file, database, etc.
        print(f"[DEBUG] Study event logged: {json.dumps(study_event, indent=2)}")
        
        return study_event

    def test_study_url_parsing(self):
        """Test study share URL parsing with sample URLs"""
        print("\n🧪 *** STUDY URL PARSING TESTS ***")
        print("Testing various study share URL formats...")
        
        # Create test URLs with encoded data (simulating the Java code)
        test_cases = [
            # Test case 1: Basic study share
            {
                'name': 'Basic Study Share',
                'studyUID': 'TEST.STUDY.123.456',
                'patientId': 'PATIENT001',
                'issuer': 'RADIOLOGY',
                'procedure': 'CT Chest with Contrast',
                'id': 'rpq-12345'
            },
            # Test case 2: Complex procedure name
            {
                'name': 'Complex Procedure',
                'studyUID': '1.2.3.4.5.6.7.8.9',
                'patientId': 'PAT-2024-001',
                'issuer': 'Emergency Department',
                'procedure': 'MRI Brain w/ & w/o Contrast + MRA',
                'id': 'rpq-67890'
            }
        ]
        
        for i, test_case in enumerate(test_cases, 1):
            print(f"\n[TEST {i}] {test_case['name']}")
            
            # Build URL like the Java code does
            study_uid_b64 = base64.b64encode(test_case['studyUID'].encode('utf-8')).decode('utf-8')
            patient_id_b64 = base64.b64encode(test_case['patientId'].encode('utf-8')).decode('utf-8')
            issuer_encoded = urllib.parse.quote(test_case['issuer'])
            procedure_encoded = urllib.parse.quote(test_case['procedure'])
            id_encoded = urllib.parse.quote(test_case['id'])
            
            test_url = f"https://share.study.link?studyUID={study_uid_b64}&patientId={patient_id_b64}&issuer={issuer_encoded}&procedure={procedure_encoded}&id={id_encoded}"
            
            print(f"Generated URL: {test_url}")
            
            # Test detection
            urls = self.detect_study_share_urls(f"Please review this study: {test_url}")
            if urls:
                print(f"✅ URL detected successfully")
                
                # Test parsing
                study_info = self.parse_study_share_url(urls[0])
                if study_info:
                    print(f"✅ URL parsed successfully")
                    
                    # Verify decoded values match original
                    print(f"\nVerification:")
                    print(f"  Original studyUID: '{test_case['studyUID']}'")
                    print(f"  Decoded studyUID:  '{study_info.get('studyUID', 'MISSING')}'")
                    print(f"  Match: {'✅' if study_info.get('studyUID') == test_case['studyUID'] else '❌'}")
                    
                    print(f"  Original patientId: '{test_case['patientId']}'")
                    print(f"  Decoded patientId:  '{study_info.get('patientId', 'MISSING')}'")
                    print(f"  Match: {'✅' if study_info.get('patientId') == test_case['patientId'] else '❌'}")
                    
                    print(f"  Original procedure: '{test_case['procedure']}'")
                    print(f"  Decoded procedure:  '{study_info.get('procedure', 'MISSING')}'")
                    print(f"  Match: {'✅' if study_info.get('procedure') == test_case['procedure'] else '❌'}")
                    
                else:
                    print(f"❌ URL parsing failed")
            else:
                print(f"❌ URL detection failed")
        
        # Test invalid URLs
        print(f"\n[TEST INVALID] Invalid URL handling")
        invalid_urls = [
            "https://not-study-link.com?studyUID=test",
            "https://share.study.link",  # No parameters
            "https://share.study.link?invalid=params"
        ]
        
        for invalid_url in invalid_urls:
            print(f"Testing invalid URL: {invalid_url}")
            urls = self.detect_study_share_urls(f"Check this: {invalid_url}")
            if urls:
                study_info = self.parse_study_share_url(urls[0])
                if study_info:
                    print(f"⚠️  Unexpectedly parsed invalid URL")
                else:
                    print(f"✅ Correctly rejected invalid URL")
            else:
                print(f"✅ Correctly ignored non-study URL")
        
        print(f"\n📊 *** STUDY URL TESTING COMPLETE ***")

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
                        # BUT allow commands that start with '/' for interactive control
                        if self.is_self_message(from_jid) and not body_text.startswith('/'):
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

    def polling_worker(self):
        """Continuous BOSH polling worker thread - runs in background"""
        print("[DEBUG] Starting polling worker thread...")
        poll_count = 0
        
        while self.running:
            try:
                poll_count += 1
                print(f"[DEBUG] Polling thread - cycle #{poll_count}")
                
                # Poll for messages (non-blocking from main thread perspective)
                messages = self.poll_messages()
                
                # Queue any messages for immediate processing
                for message in messages:
                    print(f"[DEBUG] Queuing message for immediate processing: {message['from']}")
                    self.message_queue.put(message)
                
                # Brief pause only if no messages (let BOSH handle timing otherwise)
                if not messages:
                    time.sleep(0.1)  # Very short pause to prevent CPU spinning
                    
            except Exception as e:
                print(f"❌ Polling worker error: {e}")
                print(f"[DEBUG] Error in polling thread")
                import traceback
                traceback.print_exc()
                time.sleep(5)  # Wait before retrying
        
        print("[DEBUG] Polling worker thread stopped")

    def console_input_worker(self):
        """Console input worker thread - handles direct user command input"""
        print("[DEBUG] Starting console input thread...")
        
        while self.running:
            try:
                # Show prompt and get user input
                user_input = input("Bot> ").strip()
                
                if not user_input:
                    continue
                
                # Handle special commands
                if user_input.lower() in ['quit', 'exit', 'stop']:
                    print("[*] Stopping bot...")
                    self.running = False
                    break
                elif user_input.lower() in ['help', '?']:
                    self.show_help()
                    continue
                
                # Process as command (add leading slash if missing)
                if not user_input.startswith('/'):
                    user_input = '/' + user_input
                
                print(f"[DEBUG] Processing console command: {user_input}")
                self.process_user_command(user_input)
                
            except EOFError:
                # Handle Ctrl+D
                print("\n[*] EOF received, stopping bot...")
                self.running = False
                break
            except KeyboardInterrupt:
                # Handle Ctrl+C in input thread
                print("\n[*] Interrupt received, stopping bot...")
                self.running = False
                break
            except Exception as e:
                print(f"❌ Console input error: {e}")
                # Continue processing other input
        
        print("[DEBUG] Console input thread stopped")

    def show_help(self):
        """Show help information"""
        print("\n🤖 *** XMPP AUTO-REPLY BOT COMMANDS ***")
        print("\nPresence Commands:")
        print("  status <message>      - Set status message")
        print("  show <state> [msg]    - Set show state (online/away/dnd/chat/xa)")
        print("  priority <number>     - Set presence priority")
        print("\nTesting Commands:")
        print("  test                  - Run security injection tests")
        print("  teststudy             - Test study share URL parsing")
        print("\nGeneral Commands:")
        print("  help                  - Show this help")
        print("  quit                  - Stop the bot")
        print("\nNotes:")
        print("- Commands can be typed with or without leading '/'")
        print("- XMPP messages to yourself starting with '/' also work")
        print("- Press Ctrl+C to stop at any time")
        print()

    def process_user_command(self, command_text):
        """Process interactive commands from user input"""
        parts = command_text.strip().split(' ', 2)
        command = parts[0].lower()
        
        if command == '/status':
            if len(parts) < 2:
                print("Usage: /status <message>")
                return
            status_message = ' '.join(parts[1:])
            success = self.update_presence(status_message=status_message)
            if success:
                print(f"✅ Status updated to: '{status_message}'")
            else:
                print("❌ Failed to update status")
                
        elif command == '/show':
            if len(parts) < 2:
                print("Usage: /show <state> [status_message]")
                print("Valid states: online, away, dnd, chat, xa")
                return
            show_state = parts[1]
            status_message = ' '.join(parts[2:]) if len(parts) > 2 else None
            success = self.update_presence(show_state=show_state, status_message=status_message)
            if success:
                print(f"✅ Show state updated to: '{show_state}'" + 
                      (f" with status: '{status_message}'" if status_message else ""))
            else:
                print("❌ Failed to update presence")
                
        elif command == '/test':
            print("🧪 Starting security injection tests...")
            self.test_status_injection()
            
        elif command == '/teststudy':
            print("🏥 Testing study share URL parsing...")
            self.test_study_url_parsing()
            
        elif command == '/priority':
            if len(parts) < 2:
                print("Usage: /priority <number>")
                return
            try:
                priority = int(parts[1])
                success = self.update_presence(priority=priority)
                if success:
                    print(f"✅ Priority updated to: {priority}")
                else:
                    print("❌ Failed to update priority")
            except ValueError:
                print("❌ Priority must be a number")
                
        elif command == '/help':
            print("\n🤖 Available Commands:")
            print("/status <message>     - Set status message")
            print("/show <state> [msg]  - Set show state (online/away/dnd/chat/xa)")
            print("/priority <number>   - Set presence priority")
            print("/test                - Run security injection tests")
            print("/teststudy           - Test study share URL parsing")
            print("/help                - Show this help")
            print()
            
        else:
            print(f"❌ Unknown command: {command}")
            print("Type /help for available commands")

    def message_processor(self):
        """Message processing worker thread - handles auto-replies immediately"""
        print("[DEBUG] Starting message processor thread...")
        
        while self.running:
            try:
                # Get message from queue (with timeout to allow clean shutdown)
                try:
                    message = self.message_queue.get(timeout=1.0)
                except queue.Empty:
                    continue  # Check if still running and retry
                
                print(f"\n📨 *** IMMEDIATE MESSAGE PROCESSING ***")
                print(f"From: {message['from']}")
                print(f"To: {message['to']}")
                print(f"Body: {message['body']}")
                print(f"ID: {message['id']}")
                print(f"Receipt requested: {message['receipt_requested']}")
                print(f"Timestamp: {message['timestamp']}")
                
                # Check if this is a command from our own JID (for interactive control)
                if self.is_self_message(message['from']) and message['body'].startswith('/'):
                    print("[DEBUG] Processing self-command...")
                    self.process_user_command(message['body'])
                    self.message_queue.task_done()
                    continue
                
                # Check for study share URLs in the message
                study_urls = self.detect_study_share_urls(message['body'])
                for url in study_urls:
                    study_info = self.parse_study_share_url(url)
                    if study_info:
                        self.process_study_share(message['from'], study_info)
                
                # Send receipt if requested (immediate)
                if message['receipt_requested']:
                    self.send_receipt(message['from'], message['id'])
                    print(f"✅ Sent receipt for message {message['id']}")
                
                # Generate and send auto-reply (immediate)
                reply = self.generate_auto_reply(message)
                if reply:
                    print(f"[DEBUG] Generated auto-reply: '{reply}'")
                    print(f"[DEBUG] Waiting {self.auto_reply_config['delay_seconds']} seconds before reply...")
                    time.sleep(self.auto_reply_config["delay_seconds"])
                    
                    if self.send_message(message['from'], reply):
                        print(f"🤖 Auto-replied to {message['from']}: {reply}")
                    else:
                        print(f"❌ Failed to send auto-reply to {message['from']}")
                else:
                    print("[DEBUG] No auto-reply configured for this message")
                
                # Mark task as done
                self.message_queue.task_done()
                
            except Exception as e:
                print(f"❌ Message processor error: {e}")
                print(f"[DEBUG] Error in message processing thread")
                import traceback
                traceback.print_exc()
                # Continue processing other messages
        
        print("[DEBUG] Message processor thread stopped")

    def message_loop(self):
        """Main message receiving and auto-reply loop - now with concurrent processing"""
        print("[+] Starting concurrent message processing...")
        print(f"[DEBUG] Bot JID: {self.jid}")
        print(f"[DEBUG] Session ID: {self.sid}")
        print("[DEBUG] Starting background threads for immediate response...")
        
        self.running = True
        
        try:
            # Start background polling thread
            self.polling_thread = threading.Thread(target=self.polling_worker, daemon=True)
            self.polling_thread.start()
            print("[DEBUG] Polling thread started")
            
            # Start background message processing thread
            self.processor_thread = threading.Thread(target=self.message_processor, daemon=True)
            self.processor_thread.start()
            print("[DEBUG] Message processor thread started")
            
            # Start console input thread
            self.console_thread = threading.Thread(target=self.console_input_worker, daemon=True)
            self.console_thread.start()
            print("[DEBUG] Console input thread started")
            
            print("\n🚀 *** CONCURRENT PROCESSING ACTIVE ***")
            print("📡 Polling thread: Continuous BOSH polling in background")
            print("⚡ Processor thread: Immediate auto-reply processing")
            print("💬 Console thread: Direct command input")
            print("🔥 Expected response time: ~2 seconds (configured delay)")
            print("\n🤖 *** INTERACTIVE COMMANDS ***")
            print("Type commands directly (with or without leading '/'):")
            print("  status <message>     - Set status message")
            print("  show <state> [msg]   - Set show state (online/away/dnd/chat/xa)")
            print("  priority <number>    - Set presence priority")
            print("  test                 - Run security injection tests")
            print("  help                 - Show all commands")
            print("  quit                 - Stop the bot")
            print("\nAlternatively, send yourself XMPP messages starting with '/' for remote control")
            print("\n[+] Bot is ready! Type 'help' for commands or 'quit' to stop")
            
            # Main thread waits for shutdown signal
            while self.running:
                time.sleep(0.5)
                
                # Check if all threads are still alive
                if not self.polling_thread.is_alive():
                    print("[WARNING] Polling thread died")
                if not self.processor_thread.is_alive():
                    print("[WARNING] Processor thread died")
                if not self.console_thread.is_alive():
                    print("[WARNING] Console thread died")
                    break
                
        except KeyboardInterrupt:
            print("\n[*] Stopping concurrent processing...")
            self.running = False
            
            # Wait for threads to finish
            if self.polling_thread and self.polling_thread.is_alive():
                print("[DEBUG] Waiting for polling thread to stop...")
                self.polling_thread.join(timeout=5)
            
            if self.processor_thread and self.processor_thread.is_alive():
                print("[DEBUG] Waiting for processor thread to stop...")
                self.processor_thread.join(timeout=5)
            
            if self.console_thread and self.console_thread.is_alive():
                print("[DEBUG] Waiting for console thread to stop...")
                self.console_thread.join(timeout=2)
            
            print("[DEBUG] All threads stopped")
            
        except Exception as e:
            print(f"❌ Message loop error: {e}")
            import traceback
            traceback.print_exc()
            self.running = False

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