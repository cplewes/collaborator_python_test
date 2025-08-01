#!/usr/bin/env python3
"""
Study Monitor Proof-of-Concept

This script combines XMPP message monitoring with Clario worklist integration.
When a study share URL is detected in XMPP messages, it extracts the accession
number and looks up detailed patient information from Clario.

Features:
- Threaded XMPP BOSH connection monitoring
- Automatic study share URL detection
- Async Clario integration for patient lookup
- JSON output of patient details (MRN, ULI, DOB, gender)

Usage:
    python3 study_monitor_poc.py
"""

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
import asyncio
import aiohttp
from datetime import datetime
from typing import Optional, Dict, Any, List

# === Configuration ===
BOSH_URL = "https://abpei-hub-app-north.albertahealthservices.ca:7443/http-bind/"
CLIENT_ID = "netboot"
TARGET_IDP = "LDAP1"
REALM = "EI"
KEYCLOAK_URL = f"https://abpei-hub-app-north.albertahealthservices.ca/auth/realms/{REALM}/protocol/openid-connect/token?targetIdp={TARGET_IDP}"

# Hardcoded Clario URL as requested
CLARIO_BASE_URL = "https://worklist.mic.ca"

# === Clario Integration (from clario_search_tool.py) ===

class ClarionPasswordEncoder:
    """Handle Clario's XOR password encoding."""
    
    XOR_KEY = "PasswordFieldKey"
    
    @classmethod
    def encode_password(cls, password: str) -> str:
        """Encode password using Clario's XOR + Base64 method."""
        if not password:
            raise ValueError("Password cannot be empty")
        
        key = cls.XOR_KEY
        key_len = len(key)
        xor_result = []
        
        for i, char in enumerate(password):
            key_char = key[i % key_len]
            xor_byte = ord(char) ^ ord(key_char)
            xor_result.append(xor_byte)
        
        xor_bytes = bytes(xor_result)
        encoded = base64.b64encode(xor_bytes).decode("ascii")
        return encoded

class ClarionClient:
    """Simplified Clario client for patient lookups."""
    
    def __init__(self, username: str, password: str):
        self.base_url = CLARIO_BASE_URL.rstrip("/")
        self.username = username
        self.password = password
        self.encoded_password = ClarionPasswordEncoder.encode_password(password)
        self.session: Optional[aiohttp.ClientSession] = None
        self.session_token: Optional[str] = None
        self.transaction_id = 1000
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
    
    async def connect(self) -> bool:
        """Connect and authenticate to Clario."""
        try:
            print("[*] Connecting to Clario...")
            
            # Create session
            connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                connector=connector, 
                timeout=timeout, 
                headers=self.headers
            )
            
            # Update headers for Clario
            self.session.headers.update({
                "Origin": self.base_url,
                "Referer": f"{self.base_url}/",
            })
            
            # Bootstrap session
            async with self.session.get("/") as response:
                pass  # Just get initial cookies
            
            # Login
            login_payload = {
                "data": [
                    "Login.access",
                    [self.username, self.encoded_password, "", "0"]
                ],
                "tid": self.transaction_id,
                "login": 0,
                "app": "login",
                "action": "rpc",
                "method": "direct",
            }
            
            async with self.session.post(
                "/rpc/app.php?app=login&sysClient=", 
                json=login_payload
            ) as response:
                if response.status != 200:
                    print(f"❌ Clario login failed: HTTP {response.status}")
                    return False
                
                response_data = await response.json()
                
                if isinstance(response_data, list) and len(response_data) > 0:
                    result = response_data[0].get("result", {})
                    
                    if not result.get("success"):
                        error_msg = result.get("msg", "Unknown login error")
                        print(f"❌ Clario login failed: {error_msg}")
                        return False
                    
                    login_id = int(result["loginID"])
                    self.session_token = str(login_id)
                    print(f"[+] Clario authentication successful (login_id={self.session_token})")
                    
                    # Session preparation
                    self.transaction_id += 1
                    prepare_payload = {
                        "data": ["login/Prepare.user", [login_id, None]],
                        "tid": self.transaction_id,
                        "login": login_id,
                        "app": "login",
                        "action": "rpc",
                        "method": "direct"
                    }
                    
                    async with self.session.post(
                        "/rpc/app.php?app=login&sysClient=", 
                        json=prepare_payload
                    ) as prep_response:
                        pass  # Session preparation
                    
                    return True
                
                print("❌ Unexpected Clario login response format")
                return False
                
        except Exception as e:
            print(f"❌ Clario connection failed: {e}")
            return False
    
    async def search_by_accession(self, accession: str) -> Optional[Dict[str, Any]]:
        """Search for patient details by accession number."""
        if not self.session_token:
            print("❌ Not authenticated to Clario")
            return None
        
        try:
            print(f"[*] Searching Clario for accession: {accession}")
            
            search_descriptor = {
                "params": {
                    "input": {"ws2": accession},
                    "type": "advanced",
                    "isCountOnly": False,
                    "limit": None,
                },
                "call": "search/Exam.search",
                "sort": [{"property": "defaultDirectSorting", "direction": "DESC"}],
                "operation": "user",
                "page": 1,
                "start": 0,
                "limit": "50",
            }
            
            self.transaction_id += 1
            search_payload = {
                "data": [search_descriptor],
                "tid": self.transaction_id,
                "login": int(self.session_token),
                "app": "workflow",
                "action": "rpc",
                "method": "search",
            }
            
            async with self.session.post(
                "/rpc/app.php?app=workflow&sysClient=",
                json=search_payload
            ) as response:
                if response.status != 200:
                    print(f"❌ Clario search failed: HTTP {response.status}")
                    return None
                
                response_data = await response.json()
                
                if isinstance(response_data, list) and len(response_data) > 0:
                    result = response_data[0]
                    
                    if "result" in result:
                        search_result = result["result"]
                        
                        if not search_result.get("success", False):
                            error_msg = search_result.get("error", "Search failed")
                            print(f"❌ Clario search failed: {error_msg}")
                            return None
                        
                        data = search_result.get("data", [])
                        print(f"[+] Found {len(data)} studies in Clario")
                        
                        if data:
                            # Return the first study with extracted patient info
                            study = data[0]
                            return {
                                "mrn": study.get("mrn", ""),
                                "uli": study.get("externalMrn", ""),  # _external_mrn field
                                "dob": study.get("dob", ""),  # Date of birth
                                "gender": study.get("gender", ""),  # Patient gender
                                "patient_name": study.get("name", ""),
                                "exam_id": study.get("examID", ""),
                                "raw_study": study  # Include full study data for debugging
                            }
                        else:
                            print(f"❌ No studies found for accession {accession}")
                            return None
                    else:
                        print("❌ Unexpected Clario search response")
                        return None
                
                print("❌ Invalid Clario search response format")
                return None
                
        except Exception as e:
            print(f"❌ Clario search error: {e}")
            return None
    
    async def close(self):
        """Close the Clario session."""
        if self.session and not self.session.closed:
            await self.session.close()

# === XMPP Integration (from xmpp_auto_reply.py) ===

class RIDManager:
    def __init__(self):
        self.rid = int(uuid.uuid4().int % 1e10)
    
    def next_rid(self):
        self.rid += 1
        return self.rid

class StudyMonitorPOC:
    """Integrated XMPP + Clario study monitoring system."""
    
    def __init__(self):
        # XMPP components
        self.session = requests.Session()
        self.rid_manager = RIDManager()
        self.sid = None
        self.jid = None
        self.access_token = None
        self.running = False
        
        # Threading infrastructure
        self.message_queue = queue.Queue()
        self.polling_thread = None
        self.processor_thread = None
        
        # Clario components
        self.clario_client = None
        self.clario_loop = None
        
        # Track processed messages
        self.processed_messages = set()
    
    def authenticate_xmpp(self, username: str, password: str) -> bool:
        """Authenticate with XMPP via Keycloak."""
        print("[*] Authenticating XMPP with Keycloak...")
        
        try:
            # Get access token
            token_resp = self.session.post(KEYCLOAK_URL, data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "username": username,
                "password": password,
                "scope": "openid"
            })
            token_resp.raise_for_status()
            self.access_token = token_resp.json()["access_token"]
            print("[+] Got XMPP access token")
            
            # Set up headers
            self.session.headers.update({
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "text/xml; charset=UTF-8",
                "Origin": "https://abpei-hub-app-north.albertahealthservices.ca",
                "Referer": "https://abpei-hub-app-north.albertahealthservices.ca/",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            })
            
            # Start BOSH session
            rid = self.rid_manager.next_rid()
            init_body = f"""
            <body rid='{rid}' xmlns='http://jabber.org/protocol/httpbind' to='agfa.com' xml:lang='en' wait='60' hold='1' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>
            """
            
            resp = self.session.post(BOSH_URL, data=init_body.strip())
            resp.raise_for_status()
            tree = ET.fromstring(resp.text)
            self.sid = tree.attrib["sid"]
            print(f"[+] BOSH connected, sid: {self.sid}")
            
            # SASL Authentication
            rid = self.rid_manager.next_rid()
            auth_str = f"\\x00{username}\\x00{self.access_token}"
            auth_b64 = base64.b64encode(auth_str.encode()).decode()
            auth_body = f"""
            <body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'>
              <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth_b64}</auth>
            </body>
            """
            
            auth_resp = self.session.post(BOSH_URL, data=auth_body.strip())
            auth_resp.raise_for_status()
            
            if "<success" not in auth_resp.text:
                raise Exception("SASL Authentication failed")
            print("[+] SASL Authentication successful")
            
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
            
            return True
            
        except Exception as e:
            print(f"❌ XMPP authentication failed: {e}")
            return False
    
    async def authenticate_clario(self, username: str, password: str) -> bool:
        """Authenticate with Clario."""
        self.clario_client = ClarionClient(username, password)
        return await self.clario_client.connect()
    
    def detect_study_share_urls(self, message_body: str) -> List[str]:
        """Detect study share URLs in message body."""
        if not message_body:
            return []
        
        pattern = r'https://share\\.study\\.link[^\\s]*'
        urls = re.findall(pattern, message_body, re.IGNORECASE)
        return urls
    
    def parse_study_share_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Parse study share URL and extract metadata."""
        try:
            parsed = urllib.parse.urlparse(url)
            
            if not parsed.netloc.lower() == 'share.study.link':
                return None
            
            params = urllib.parse.parse_qs(parsed.query)
            
            # Validate required parameters
            required_params = ['studyUID', 'patientId', 'issuer', 'procedure', 'id']
            missing_params = [param for param in required_params if param not in params]
            
            if missing_params:
                print(f"[DEBUG] Missing required parameters: {missing_params}")
                return None
            
            study_info = {}
            
            # Extract and decode parameters
            if 'studyUID' in params:
                try:
                    study_uid_b64 = params['studyUID'][0]
                    study_info['studyUID'] = base64.b64decode(study_uid_b64).decode('utf-8')
                except Exception:
                    study_info['studyUID'] = study_uid_b64
            
            if 'patientId' in params:
                try:
                    patient_id_b64 = params['patientId'][0]
                    study_info['patientId'] = base64.b64decode(patient_id_b64).decode('utf-8')
                except Exception:
                    study_info['patientId'] = patient_id_b64
            
            if 'procedure' in params:
                study_info['procedure'] = urllib.parse.unquote(params['procedure'][0])
            
            # Add other fields
            for field in ['issuer', 'id']:
                if field in params:
                    study_info[field] = urllib.parse.unquote(params[field][0])
            
            study_info['raw_url'] = url
            return study_info
            
        except Exception as e:
            print(f"❌ Failed to parse study share URL: {e}")
            return None
    
    def extract_accession_from_procedure(self, procedure: str) -> Optional[str]:
        """Extract accession number (last word) from procedure string."""
        if not procedure:
            return None
        
        # Split by whitespace and get the last word
        words = procedure.strip().split()
        if words:
            accession = words[-1]
            print(f"[DEBUG] Extracted accession '{accession}' from procedure: {procedure}")
            return accession
        
        return None
    
    async def process_study_share(self, from_jid: str, study_info: Dict[str, Any]):
        """Process a detected study share and lookup patient details."""
        print(f"\\n🏥 *** STUDY SHARE DETECTED ***")
        print(f"From: {from_jid}")
        print(f"Study UID: {study_info.get('studyUID', 'N/A')}")
        print(f"Procedure: {study_info.get('procedure', 'N/A')}")
        
        # Extract accession from procedure (last word)
        procedure = study_info.get('procedure', '')
        accession = self.extract_accession_from_procedure(procedure)
        
        if not accession:
            print("❌ Could not extract accession from procedure")
            return
        
        # Look up patient details in Clario
        patient_details = await self.clario_client.search_by_accession(accession)
        
        # Generate JSON output
        output = {
            "timestamp": datetime.now().isoformat(),
            "accession": accession,
            "patient": {
                "mrn": patient_details.get("mrn", "") if patient_details else "",
                "uli": patient_details.get("uli", "") if patient_details else "",
                "dob": patient_details.get("dob", "") if patient_details else "",
                "gender": patient_details.get("gender", "") if patient_details else ""
            },
            "source": {
                "from_jid": from_jid,
                "study_url": study_info.get('raw_url', ''),
                "study_uid": study_info.get('studyUID', ''),
                "procedure": procedure
            }
        }
        
        print("\\n📊 *** PATIENT LOOKUP RESULT ***")
        print(json.dumps(output, indent=2))
    
    def poll_messages(self) -> List[Dict[str, Any]]:
        """Poll for incoming XMPP messages."""
        if not self.sid:
            return []
        
        rid = self.rid_manager.next_rid()
        poll_body = f"""<body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind' wait='60' hold='1'/>"""
        
        try:
            resp = self.session.post(BOSH_URL, data=poll_body.strip(), timeout=65)
            resp.raise_for_status()
            
            messages = []
            root = ET.fromstring(resp.text)
            
            for message in root.iter():
                if message.tag.endswith('message') and message.get('type') == 'chat':
                    from_jid = message.get('from', '')
                    to_jid = message.get('to', '')
                    msg_id = message.get('id', '')
                    
                    body_text = ''
                    for elem in message.iter():
                        if elem.tag.endswith('body'):
                            body_text = elem.text or ''
                            break
                    
                    if body_text and from_jid:
                        if msg_id not in self.processed_messages:
                            message_data = {
                                'from': from_jid,
                                'to': to_jid,
                                'body': body_text,
                                'id': msg_id or f"auto_{int(time.time() * 1000)}",
                                'timestamp': datetime.now()
                            }
                            messages.append(message_data)
                            self.processed_messages.add(msg_id)
            
            return messages
            
        except Exception as e:
            print(f"❌ Polling error: {e}")
            return []
    
    def polling_worker(self):
        """XMPP polling worker thread."""
        print("[DEBUG] Starting XMPP polling thread...")
        
        while self.running:
            try:
                messages = self.poll_messages()
                for message in messages:
                    self.message_queue.put(message)
                
                if not messages:
                    time.sleep(0.1)
                    
            except Exception as e:
                print(f"❌ Polling worker error: {e}")
                time.sleep(5)
        
        print("[DEBUG] XMPP polling thread stopped")
    
    def message_processor(self):
        """Message processing worker thread."""
        print("[DEBUG] Starting message processor thread...")
        
        # Create event loop for Clario async operations
        self.clario_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.clario_loop)
        
        while self.running:
            try:
                try:
                    message = self.message_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                print(f"\\n📨 *** MESSAGE RECEIVED ***")
                print(f"From: {message['from']}")
                print(f"Body: {message['body']}")
                
                # Check for study share URLs
                study_urls = self.detect_study_share_urls(message['body'])
                for url in study_urls:
                    study_info = self.parse_study_share_url(url)
                    if study_info:
                        # Process study share asynchronously
                        self.clario_loop.run_until_complete(
                            self.process_study_share(message['from'], study_info)
                        )
                
                self.message_queue.task_done()
                
            except Exception as e:
                print(f"❌ Message processor error: {e}")
        
        # Close Clario client
        if self.clario_client:
            self.clario_loop.run_until_complete(self.clario_client.close())
        
        self.clario_loop.close()
        print("[DEBUG] Message processor thread stopped")
    
    def start_monitoring(self):
        """Start the monitoring system."""
        print("\\n🚀 *** STARTING STUDY MONITORING ***")
        print("Monitoring XMPP messages for study shares...")
        print("Will automatically lookup patient details in Clario")
        print("Press Ctrl+C to stop")
        
        self.running = True
        
        try:
            # Start threads
            self.polling_thread = threading.Thread(target=self.polling_worker, daemon=True)
            self.polling_thread.start()
            
            self.processor_thread = threading.Thread(target=self.message_processor, daemon=True)
            self.processor_thread.start()
            
            # Main loop
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\\n[*] Stopping study monitoring...")
            self.running = False
            
            # Wait for threads
            if self.polling_thread and self.polling_thread.is_alive():
                self.polling_thread.join(timeout=5)
            
            if self.processor_thread and self.processor_thread.is_alive():
                self.processor_thread.join(timeout=5)
            
            print("[DEBUG] All threads stopped")

# === Main Application ===

def main():
    """Main application entry point."""
    print("=== Study Monitor Proof-of-Concept ===")
    print("Integrates XMPP monitoring with Clario patient lookup")
    
    # Get XMPP credentials
    print("\\n--- XMPP Authentication ---")
    xmpp_username = input("XMPP Username: ")
    xmpp_password = getpass.getpass("XMPP Password: ")
    
    # Get Clario credentials
    print("\\n--- Clario Authentication ---")
    clario_username = input("Clario Username: ")
    clario_password = getpass.getpass("Clario Password: ")
    
    # Create monitor
    monitor = StudyMonitorPOC()
    
    # Authenticate XMPP
    if not monitor.authenticate_xmpp(xmpp_username, xmpp_password):
        print("❌ XMPP authentication failed")
        return
    
    # Authenticate Clario
    clario_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(clario_loop)
    
    if not clario_loop.run_until_complete(monitor.authenticate_clario(clario_username, clario_password)):
        print("❌ Clario authentication failed")
        return
    
    clario_loop.close()
    
    print("\\n✅ Both systems authenticated successfully!")
    
    # Start monitoring
    monitor.start_monitoring()

if __name__ == "__main__":
    main()