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
import urllib.parse
import uuid

# === Configuration ===
BOSH_URL = "https://abpei-hub-app-north.albertahealthservices.ca:7443/http-bind/"
CLIENT_ID = "netboot"
TARGET_IDP = "LDAP1"
REALM = "EI"
KEYCLOAK_URL = f"https://abpei-hub-app-north.albertahealthservices.ca/auth/realms/{REALM}/protocol/openid-connect/token?targetIdp={TARGET_IDP}"

# Hardcoded Clario URL as requested
CLARIO_BASE_URL = "https://worklist.mic.ca"

# Google Forms configuration
XOR_KEY = "micphone"
GOOGLE_FORM_BASE_URL = "https://docs.google.com/forms/d/e/1FAIpQLSe45evjTBqYBDJtcNLp221-QUp91a_KFgJJEZOFKIn4AxtF8g/viewform"

# === Clario Integration (embedded from clario_search_tool.py) ===

import logging
from dataclasses import dataclass
from typing import Union, Tuple

# Set up basic logging for Clario
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class Study:
    """Study data model."""
    exam_id: str
    patient_name: str
    patient_id: str
    accession: str
    exam_date: str
    exam_time: str
    modality: str
    priority: str
    status: str
    description: str
    
    @classmethod
    def from_clario_data_with_extras(cls, data: Dict[str, Any]) -> 'Study':
        """Create Study with extra fields stored."""
        study = cls(
            exam_id=str(data.get('examID', '')),
            patient_name=data.get('name', ''),
            patient_id=str(data.get('patientID', '')),
            accession=data.get('accession', ''),
            exam_date=data.get('time', '').split(' ')[0] if data.get('time') else '',
            exam_time=data.get('time', '').split(' ', 1)[1] if data.get('time') and ' ' in data.get('time', '') else '',
            modality=data.get('group', '').strip(),
            priority=data.get('priority', ''),
            status=data.get('status', ''),
            description=data.get('procedureName', data.get('siteProcedure', ''))
        )
        
        # Store additional useful fields
        study._mrn = data.get('mrn', '')
        study._external_mrn = data.get('externalMrn', '')
        study._dob = data.get('dob', '')
        study._gender = data.get('gender', '')
        study._age = data.get('age', '')
        study._site = data.get('site', '')
        study._assigned_to = data.get('assign', '')
        
        return study

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

class ClarionSearchTool:
    """Clario search tool for exam lookup."""
    
    def __init__(self, base_url: str, username: str, password: str):
        """Initialize the Clario search tool."""
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.encoded_password = ClarionPasswordEncoder.encode_password(password)
        self.session: Optional[aiohttp.ClientSession] = None
        self.session_token: Optional[str] = None
        self.transaction_id = 1000
        
        # Headers for Clario API
        self.headers = {
            "User-Agent": "Clario-Search-Tool/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate"
        }
    
    async def connect(self) -> None:
        """Create HTTP session and login to Clario."""
        logger.info("Connecting to Clario server: %s", self.base_url)
        
        # Create session with connection pooling
        connector = aiohttp.TCPConnector(
            limit=10,
            limit_per_host=5,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            connector=connector, 
            timeout=timeout, 
            headers=self.headers
        )
        
        # Bootstrap session first (get initial cookies)
        await self.bootstrap()
        
        # Login to Clario
        await self.login()
    
    async def bootstrap(self) -> bool:
        """Get initial session cookies."""
        logger.info("Bootstrapping session...")
        try:
            status_code, response_data, headers = await self._make_request("GET", "/")
            logger.info("Session initialized successfully")
            return True
        except Exception as e:
            logger.warning("Bootstrap warning: %s", str(e))
            return False
    
    async def close(self) -> None:
        """Close HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
            logger.info("Session closed")
    
    def _get_next_transaction_id(self) -> int:
        """Get next transaction ID for RPC calls."""
        self.transaction_id += 1
        return self.transaction_id
    
    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Tuple[int, Union[Dict, str], Dict[str, str]]:
        """Make HTTP request with error handling."""
        url = f"{self.base_url}{endpoint}"
        
        logger.debug("Making %s request to: %s", method, url)
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                status_code = response.status
                response_headers = dict(response.headers)
                
                # Get response text
                response_text = await response.text()
                
                logger.debug("Response: status=%d, size=%d bytes", status_code, len(response_text))
                
                if status_code >= 400:
                    raise Exception(f"HTTP {status_code}: {response_text[:200]}")
                
                # Try to parse as JSON
                if response_text.strip().startswith(('{', '[')):
                    try:
                        response_data = json.loads(response_text)
                    except json.JSONDecodeError:
                        response_data = response_text
                else:
                    response_data = response_text
                
                return status_code, response_data, response_headers
                
        except aiohttp.ClientError as e:
            raise Exception(f"Request failed: {e}")
        except asyncio.TimeoutError:
            raise Exception("Request timed out")
    
    async def login(self) -> None:
        """Login to Clario using RPC method."""
        logger.info("Logging in to Clario as user: %s", self.username)
        
        # Update headers to match Clario requirements
        clario_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Ch-Ua": '"Chromium";v="136", "Microsoft Edge";v="136", "Not.A/Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "dev": "1",
            "last": "0.692",
            "opt": "log",
        }
        
        # Update session headers
        self.session.headers.update(clario_headers)
        
        # Prepare RPC login payload
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
        
        # Make RPC login request
        rpc_url = f"/rpc/app.php?app=login&sysClient="
        status_code, response_data, headers = await self._make_request(
            "POST", 
            rpc_url, 
            json=login_payload
        )
        
        logger.info("Login response received: status=%d", status_code)
        logger.debug("Login response data: %s", response_data)
        
        # Parse RPC response
        if isinstance(response_data, list) and len(response_data) > 0:
            result = response_data[0].get("result", {})
            
            if not result.get("success"):
                error_msg = result.get("msg", "Unknown login error")
                raise Exception(f"Login failed: {error_msg}")
            
            # Store login ID for subsequent requests
            login_id = int(result["loginID"])
            self.session_token = str(login_id)
            logger.info("Successfully logged in to Clario (login_id=%s)", self.session_token)
            
            # Step 2: Prepare user session
            logger.debug("Starting session preparation for login_id: %d", login_id)
            
            prepare_payload = {
                "data": [
                    "login/Prepare.user",
                    [login_id, None]
                ],
                "tid": self._get_next_transaction_id(),
                "login": login_id,
                "app": "login",
                "action": "rpc",
                "method": "direct"
            }
            
            prepare_url = f"/rpc/app.php?app=login&sysClient="
            status_code, prepare_response, headers = await self._make_request(
                "POST",
                prepare_url,
                json=prepare_payload
            )
            
            logger.debug("Session preparation response: status=%d", status_code)
            
        else:
            raise Exception(f"Unexpected login response format: {type(response_data)}")
    
    async def search_exam_by_accession(self, accession: str) -> List[Study]:
        """Search for exams by accession number using Clario RPC."""
        logger.info("Searching for exam with accession: %s", accession)
        
        if not self.session_token:
            raise Exception("Not logged in - no session token")
        
        # Build search descriptor
        search_descriptor = {
            "params": {
                "input": {
                    "ws2": accession
                },
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
        
        # Prepare RPC search payload
        search_payload = {
            "data": [search_descriptor],
            "tid": self._get_next_transaction_id(),
            "login": int(self.session_token),
            "app": "workflow",
            "action": "rpc",
            "method": "search",
        }
        
        # Make RPC search request
        rpc_url = f"/rpc/app.php?app=workflow&sysClient="
        status_code, response_data, headers = await self._make_request(
            "POST",
            rpc_url,
            json=search_payload
        )
        
        logger.info("Search response received: status=%d", status_code)
        
        studies = []
        
        # Parse RPC response
        if isinstance(response_data, list) and len(response_data) > 0:
            result = response_data[0]
            
            if "result" in result:
                search_result = result["result"]
                
                if not search_result.get("success", False):
                    error_msg = search_result.get("error", "Search failed")
                    logger.warning("Search failed: %s", error_msg)
                    return studies
                
                # Parse studies from data
                data = search_result.get("data", [])
                logger.debug("Found %d study records in search response", len(data))
                
                for exam_data in data:
                    try:
                        study = Study.from_clario_data_with_extras(exam_data)
                        studies.append(study)
                        logger.debug("Parsed study: exam_id=%s, patient=%s, accession=%s", 
                                   study.exam_id, study.patient_name, study.accession)
                    except Exception as e:
                        logger.warning("Failed to parse exam data: %s", e)
                        
            elif "error" in result:
                error_msg = result["error"]
                logger.error("Search RPC error: %s", error_msg)
                raise Exception(f"Search failed: {error_msg}")
            else:
                logger.error("Unexpected search response format")
                raise Exception("Unexpected search response format")
        else:
            logger.error("Invalid search response structure")
            raise Exception("Invalid search response structure")
        
        logger.info("Found %d studies for accession %s", len(studies), accession)
        return studies

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
        self.heartbeat_thread = None
        
        # Clario components (will be created in message processor thread)
        self.clario_tool = None
        self.clario_loop = None
        self.clario_login_id = None
        self.clario_credentials = None  # Store credentials for later authentication
        
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
            auth_str = f"\x00{username}\x00{self.access_token}"
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
            
            # Set high priority presence to receive messages (fix for multi-client conflicts)
            self.set_high_priority_presence()
            
            return True
            
        except Exception as e:
            print(f"❌ XMPP authentication failed: {e}")
            return False
    
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
            <status>Study Monitor POC active</status>
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
    
    def set_clario_credentials(self, username: str, password: str):
        """Store Clario credentials for later authentication in message processor thread."""
        self.clario_credentials = (username, password)
        print(f"[+] Clario credentials stored for user: {username}")
    
    async def authenticate_clario_in_thread(self) -> bool:
        """Authenticate with Clario in the message processor thread's event loop."""
        if not self.clario_credentials:
            print("❌ No Clario credentials available")
            return False
            
        username, password = self.clario_credentials
        print(f"[*] Authenticating with Clario as: {username}")
        
        try:
            self.clario_tool = ClarionSearchTool(CLARIO_BASE_URL, username, password)
            await self.clario_tool.connect()
            
            # Extract login_id for heartbeat functionality
            if hasattr(self.clario_tool, 'session_token') and self.clario_tool.session_token:
                self.clario_login_id = int(self.clario_tool.session_token)
                print(f"[+] Clario authentication successful (login_id={self.clario_login_id})")
            else:
                print("[+] Clario authentication successful")
            
            return True
        except Exception as e:
            print(f"❌ Clario authentication failed: {e}")
            return False
    
    async def _rpc_call(self, app: str, method: str, params: List, method_type: str = "direct"):
        """Helper method for Clario RPC calls with detailed logging."""
        if not self.clario_tool or not self.clario_tool.session:
            raise Exception("Clario not connected")
        
        # Match working client payload structure exactly
        payload = {
            "action": "rpc",
            "method": method_type,
            "data": [method, params],
            "tid": self.clario_tool._get_next_transaction_id(),
            "app": app,
            "login": self.clario_login_id if self.clario_login_id else 0,
        }
        
        # Debug logging for RPC requests (redact sensitive data)
        debug_payload = {**payload, "data": [method, "[ARGS_REDACTED]" if params else []]}
        logger.debug("RPC Request: %s", json.dumps(debug_payload, indent=2))
        
        rpc_url = f"/rpc/app.php?app={app}&sysClient="
        logger.debug("RPC URL: %s", rpc_url)
        
        try:
            status_code, response_data, headers = await self.clario_tool._make_request(
                "POST", rpc_url, json=payload
            )
            
            logger.debug("RPC Response: status=%d, type=%s", status_code, type(response_data).__name__)
            
            # Parse response like working client
            if isinstance(response_data, list) and len(response_data) > 0:
                result = response_data[0]
                logger.debug("RPC response keys: %s", list(result.keys()) if isinstance(result, dict) else "non-dict")
                
                if "result" in result:
                    logger.debug("RPC call successful (app=%s, method=%s)", app, method)
                    return result["result"]
                elif "error" in result:
                    error_msg = result["error"]
                    logger.error("RPC call failed (app=%s, method=%s): %s", app, method, error_msg)
                    raise Exception(f"RPC Error: {error_msg}")
                else:
                    logger.error("No result or error in RPC response: %s", result)
                    raise Exception(f"No result or error in RPC response: {result}")
            else:
                logger.error("Unexpected RPC response format (app=%s, method=%s): %s", app, method, response_data)
                raise Exception(f"Unexpected response format: {response_data}")
                
        except Exception as e:
            logger.error("RPC call failed for %s.%s: %s", app, method, str(e))
            raise
    
    async def heartbeat(self) -> bool:
        """Send keep-alive heartbeat to Clario."""
        if not self.clario_login_id:
            logger.debug("Heartbeat skipped - not logged in")
            return False

        logger.debug("Sending heartbeat for login_id: %d", self.clario_login_id)

        try:
            # Try using session preparation as heartbeat (matches working client pattern)
            result = await self._rpc_call(
                "login", "login/Prepare.user", [self.clario_login_id, None], method_type="direct"
            )
            logger.debug("Heartbeat successful (result=%s)", result)
            return True
        except Exception as e:
            logger.error("Heartbeat failed: %s", str(e))
            return False
    
    async def get_patient_info(self, patient_id: str, exam_id: str) -> Dict[str, Any]:
        """Get detailed patient information using Clario RPC."""
        logger.debug("Fetching patient info for patient_id: %s, exam_id: %s", patient_id, exam_id)
        
        if not self.clario_login_id:
            raise Exception("Not logged in - no login_id")
        
        try:
            # Use exact RPC format provided by user
            result = await self._rpc_call(
                "workflow", ">workflow/patient/Info.get", [patient_id, exam_id, False], method_type="one"
            )
            
            logger.debug("Patient info RPC successful")
            
            # Parse patient information from result.information
            if isinstance(result, dict) and "information" in result:
                patient_info = result["information"]
                logger.debug("Patient demographics: %s", patient_info)
                return patient_info
            else:
                logger.warning("No information section in patient info response: %s", result)
                return {}
                
        except Exception as e:
            logger.error("Failed to get patient info for patient_id=%s, exam_id=%s: %s", patient_id, exam_id, str(e))
            return {}
    
    def xor_encrypt(self, text: str, key: str) -> str:
        """XOR encrypt text with key (port of JavaScript xorEncrypt function)."""
        result = ''
        for i in range(len(text)):
            xor_char = ord(text[i]) ^ ord(key[i % len(key)])
            result += chr(xor_char)
        return result
    
    def build_patient_json(self, name: str, uli: str, dob: str, gender: str, mrn: str) -> str:
        """Build patient JSON string for Google Forms payload."""
        patient_data = {
            "name": name,
            "ULI": uli,
            "date_of_birth": dob,
            "gender": gender,
            "MRN": mrn
        }
        return json.dumps(patient_data)
    
    def build_google_form_url(self, encoded_payload: str, username: str, physician: str) -> str:
        """Build Google Forms URL with encoded patient data."""
        params = {
            "usp": "pp_url",
            "entry.420020934": physician,
            "entry.1660492748": username, 
            "entry.1126175213": encoded_payload
        }
        
        query_string = urllib.parse.urlencode(params)
        return f"{GOOGLE_FORM_BASE_URL}?{query_string}"
    
    def generate_google_forms_link(self, patient_details: Dict[str, Any], username: str, physician: str = "Unknown") -> str:
        """Generate encrypted Google Forms link with patient data."""
        print(f"[DEBUG] Generating Google Forms link for user: {username}, physician: {physician}")
        
        # Build patient JSON
        json_str = self.build_patient_json(
            patient_details.get("patient_name", ""),
            patient_details.get("uli", ""),
            patient_details.get("dob", ""),
            patient_details.get("gender", ""),
            patient_details.get("mrn", "")
        )
        print(f"[DEBUG] Patient JSON: {json_str}")
        
        # XOR encrypt with key
        encrypted = self.xor_encrypt(json_str, XOR_KEY)
        print(f"[DEBUG] Encrypted length: {len(encrypted)} bytes")
        
        # Base64 encode
        encoded = base64.b64encode(encrypted.encode('latin1')).decode('ascii')
        print(f"[DEBUG] Base64 encoded length: {len(encoded)} chars")
        
        # Build Google Forms URL
        form_url = self.build_google_form_url(encoded, username, physician)
        print(f"[DEBUG] Generated Google Forms URL: {form_url[:100]}...")
        
        return form_url
    
    def extract_username_from_jid(self, jid: str) -> str:
        """Extract username from JID (e.g., 'kiranreddy' from 'kiranreddy@agfa.com/resource')."""
        if '@' in jid:
            return jid.split('@')[0]
        return jid
    
    def send_xmpp_reply(self, to_jid: str, message: str) -> bool:
        """Send XMPP reply message to the specified JID."""
        if not self.sid or not self.jid:
            print("[DEBUG] Cannot send reply - no XMPP session or JID")
            return False
        
        print(f"[DEBUG] Sending XMPP reply to: {to_jid}")
        print(f"[DEBUG] Reply message: {message[:100]}{'...' if len(message) > 100 else ''}")
        
        # Generate unique message ID
        message_id = str(uuid.uuid4())
        rid = self.rid_manager.next_rid()
        
        # Build message structure matching working BOSH requests
        reply_body = f"""<body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind'><message from='{self.jid}' id='{message_id}' to='{to_jid}' type='chat' xmlns='jabber:client'><body>{message}</body><active xmlns='http://jabber.org/protocol/chatstates'/><request xmlns='urn:xmpp:receipts'/><origin-id id='{message_id}' xmlns='urn:xmpp:sid:0'/></message></body>"""
        
        print(f"[DEBUG] XMPP reply XML: {reply_body[:200]}...")
        
        # Use the same headers as BOSH polling (including Authorization)
        reply_headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "text/xml; charset=UTF-8",
            "Origin": "https://abpei-hub-app-north.albertahealthservices.ca",
            "Referer": "https://abpei-hub-app-north.albertahealthservices.ca/",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        }
        
        try:
            resp = requests.post(BOSH_URL, data=reply_body, headers=reply_headers)
            resp.raise_for_status()
            print(f"[+] XMPP reply sent successfully to {to_jid}")
            print(f"[DEBUG] Reply response: {resp.status_code}, {resp.text[:100]}...")
            return True
        except Exception as e:
            print(f"❌ Failed to send XMPP reply: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"[DEBUG] Error response: {e.response.status_code}, {e.response.text[:200]}...")
            return False
    
    def detect_study_share_urls(self, message_body: str) -> List[str]:
        """Detect study share URLs in message body."""
        if not message_body:
            return []
        
        # Fixed regex pattern - use single backslashes for proper escaping
        pattern = r'https://share\.study\.link[^\s]*'
        urls = re.findall(pattern, message_body, re.IGNORECASE)
        
        if urls:
            print(f"[DEBUG] Detected {len(urls)} study share URL(s): {urls}")
        else:
            print(f"[DEBUG] No study share URLs found in message: '{message_body[:100]}{'...' if len(message_body) > 100 else ''}'")
        
        return urls
    
    def parse_study_share_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Parse study share URL and extract metadata."""
        print(f"[DEBUG] Parsing study share URL: {url}")
        
        try:
            parsed = urllib.parse.urlparse(url)
            print(f"[DEBUG] Parsed URL - netloc: {parsed.netloc}, query: {parsed.query}")
            
            if not parsed.netloc.lower() == 'share.study.link':
                print(f"[DEBUG] Wrong netloc: expected 'share.study.link', got '{parsed.netloc}'")
                return None
            
            params = urllib.parse.parse_qs(parsed.query)
            print(f"[DEBUG] URL parameters: {list(params.keys())}")
            
            # Validate required parameters
            required_params = ['studyUID', 'patientId', 'issuer', 'procedure', 'id']
            missing_params = [param for param in required_params if param not in params]
            
            if missing_params:
                print(f"[DEBUG] Missing required parameters: {missing_params}")
                print(f"[DEBUG] Available parameters: {list(params.keys())}")
                return None
            
            study_info = {}
            
            # Extract and decode parameters
            if 'studyUID' in params:
                try:
                    study_uid_b64 = params['studyUID'][0]
                    study_info['studyUID'] = base64.b64decode(study_uid_b64).decode('utf-8')
                    print(f"[DEBUG] Decoded studyUID: {study_info['studyUID']}")
                except Exception as e:
                    print(f"[DEBUG] Failed to decode studyUID, using raw: {e}")
                    study_info['studyUID'] = study_uid_b64
            
            if 'patientId' in params:
                try:
                    patient_id_b64 = params['patientId'][0]
                    study_info['patientId'] = base64.b64decode(patient_id_b64).decode('utf-8')
                    print(f"[DEBUG] Decoded patientId: {study_info['patientId']}")
                except Exception as e:
                    print(f"[DEBUG] Failed to decode patientId, using raw: {e}")
                    study_info['patientId'] = patient_id_b64
            
            if 'procedure' in params:
                raw_procedure = params['procedure'][0]
                study_info['procedure'] = urllib.parse.unquote(raw_procedure)
                print(f"[DEBUG] Decoded procedure: '{study_info['procedure']}'")
            
            # Add other fields
            for field in ['issuer', 'id']:
                if field in params:
                    study_info[field] = urllib.parse.unquote(params[field][0])
                    print(f"[DEBUG] Decoded {field}: {study_info[field]}")
            
            study_info['raw_url'] = url
            print(f"[DEBUG] Successfully parsed study info: {study_info}")
            return study_info
            
        except Exception as e:
            print(f"❌ Failed to parse study share URL: {e}")
            print(f"[DEBUG] URL that failed: {url}")
            import traceback
            print(f"[DEBUG] Full error: {traceback.format_exc()}")
            return None
    
    def extract_accession_from_procedure(self, procedure: str) -> Optional[str]:
        """Extract accession number (last word) from procedure string."""
        if not procedure:
            print(f"[DEBUG] No procedure provided for accession extraction")
            return None
        
        print(f"[DEBUG] Extracting accession from procedure: '{procedure}'")
        
        # Split by whitespace and get the last word
        words = procedure.strip().split()
        if words:
            accession = words[-1]
            print(f"[DEBUG] Extracted accession '{accession}' from procedure: {procedure}")
            print(f"[DEBUG] All words in procedure: {words}")
            return accession
        else:
            print(f"[DEBUG] No words found in procedure string")
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
        try:
            studies = await self.clario_tool.search_exam_by_accession(accession)
            if studies:
                # Get the first study and extract basic info
                study = studies[0]
                print(f"[+] Found exam in Clario: exam_id={study.exam_id}, patient_id={study.patient_id}")
                
                # Get detailed patient demographics using the correct RPC call
                patient_info = await self.get_patient_info(study.patient_id, study.exam_id)
                
                if patient_info:
                    patient_details = {
                        "mrn": patient_info.get("mrn", ""),
                        "uli": getattr(study, '_external_mrn', ''),  # Still use external MRN from exam search
                        "dob": patient_info.get("dob", ""),  # From patient info RPC
                        "gender": patient_info.get("gender", ""),  # From patient info RPC
                        "patient_name": patient_info.get("name", study.patient_name),  # Prefer full name from patient info
                        "exam_id": study.exam_id,
                        "patient_id": study.patient_id,
                    }
                    print(f"[+] Found complete patient details: {patient_details}")
                else:
                    # Fallback to basic study info if patient info RPC fails
                    patient_details = {
                        "mrn": getattr(study, '_mrn', ''),
                        "uli": getattr(study, '_external_mrn', ''),
                        "dob": "",  # Empty if we can't get patient info
                        "gender": "",  # Empty if we can't get patient info
                        "patient_name": study.patient_name,
                        "exam_id": study.exam_id,
                        "patient_id": study.patient_id,
                    }
                    print(f"[+] Found basic patient details (no demographics): {patient_details}")
            else:
                print(f"❌ No studies found for accession {accession}")
                patient_details = None
        except Exception as e:
            print(f"❌ Clario search error: {e}")
            patient_details = None
        
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
        
        # Generate Google Forms link and send reply if we have patient details
        if patient_details:
            print("\\n🔗 *** GENERATING GOOGLE FORMS LINK ***")
            
            # Extract username from sender JID
            username = self.extract_username_from_jid(from_jid)
            
            # Use procedure as physician name (could be enhanced later)
            physician = study_info.get('procedure', 'Unknown Procedure')
            
            # Generate encrypted Google Forms link
            try:
                forms_link = self.generate_google_forms_link(patient_details, username, physician)
                
                # Send XMPP reply with the Google Forms link
                reply_message = f"Google Forms link for patient data: {forms_link}"
                success = self.send_xmpp_reply(from_jid, reply_message)
                
                if success:
                    print("\\n✅ *** GOOGLE FORMS LINK SENT SUCCESSFULLY ***")
                else:
                    print("\\n❌ *** FAILED TO SEND GOOGLE FORMS LINK ***")
                    
            except Exception as e:
                print(f"\\n❌ *** GOOGLE FORMS LINK GENERATION FAILED: {e} ***")
        else:
            print("\\n⚠️  No patient details available - skipping Google Forms link generation")
    
    def poll_messages(self) -> List[Dict[str, Any]]:
        """Poll for incoming XMPP messages with comprehensive debugging."""
        if not self.sid:
            print("[DEBUG] Cannot poll - no session ID")
            return []
        
        rid = self.rid_manager.next_rid()
        poll_body = f"""<body rid='{rid}' sid='{self.sid}' xmlns='http://jabber.org/protocol/httpbind' wait='60' hold='1'/>"""
        
        poll_start = time.time()
        print(f"[DEBUG] BOSH Poll Request (RID: {rid}): Starting long-poll to {BOSH_URL}")
        
        try:
            resp = self.session.post(BOSH_URL, data=poll_body.strip(), timeout=65)
            poll_duration = time.time() - poll_start
            resp.raise_for_status()
            
            print(f"[DEBUG] BOSH Poll Response: Status={resp.status_code}, Duration={poll_duration:.2f}s, Size={len(resp.text)} bytes")
            
            # Debug the raw response periodically
            if int(time.time()) % 30 == 0:  # Every 30 seconds
                print(f"[DEBUG] Raw BOSH Response: {resp.text[:200]}{'...' if len(resp.text) > 200 else ''}")
            
            messages = []
            root = ET.fromstring(resp.text)
            
            # Check for ack attribute in response
            ack_value = root.get('ack')
            if ack_value:
                print(f"[DEBUG] Server ACK: {ack_value}")
            
            # Count total elements for debugging
            total_elements = len(list(root.iter()))
            message_elements = 0
            
            for message in root.iter():
                if message.tag.endswith('message') and message.get('type') == 'chat':
                    message_elements += 1
                    from_jid = message.get('from', '')
                    to_jid = message.get('to', '')
                    msg_id = message.get('id', '')
                    
                    body_text = ''
                    for elem in message.iter():
                        if elem.tag.endswith('body'):
                            body_text = elem.text or ''
                            break
                    
                    print(f"[DEBUG] Message Element: From={from_jid}, To={to_jid}, ID={msg_id}")
                    print(f"[DEBUG] Message Body Preview: '{body_text[:50]}{'...' if len(body_text) > 50 else ''}'")
                    
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
                            print(f"[DEBUG] Added message to queue: {msg_id}")
                        else:
                            print(f"[DEBUG] Skipped duplicate message: {msg_id}")
            
            print(f"[DEBUG] BOSH Parse Summary: {total_elements} total elements, {message_elements} message elements, {len(messages)} new messages")
            
            if len(messages) == 0:
                print("[DEBUG] Empty poll response - waiting for next cycle")
            
            return messages
            
        except requests.exceptions.Timeout:
            poll_duration = time.time() - poll_start
            print(f"[DEBUG] BOSH poll timeout after {poll_duration:.2f}s (normal for long-polling)")
            return []
        except Exception as e:
            poll_duration = time.time() - poll_start  
            print(f"❌ Polling error after {poll_duration:.2f}s: {e}")
            print(f"[DEBUG] Error type: {type(e).__name__}")
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
    
    def heartbeat_worker(self):
        """Clario heartbeat worker thread - sends periodic keep-alives."""
        print("[DEBUG] Starting Clario heartbeat thread...")
        
        # Wait for message processor thread to set up event loop
        print("[DEBUG] Waiting for message processor event loop to be ready...")
        loop_wait_count = 0
        while self.running and (not self.clario_loop or self.clario_loop.is_closed()):
            time.sleep(1)
            loop_wait_count += 1
            if loop_wait_count % 5 == 0:  # Log every 5 seconds
                print(f"[DEBUG] Still waiting for event loop... ({loop_wait_count}s)")
            if loop_wait_count > 30:  # Give up after 30 seconds
                print("[DEBUG] Timeout waiting for event loop - heartbeat disabled")
                return
        
        if self.clario_loop:
            print("[DEBUG] Event loop ready - heartbeat enabled")
        
        heartbeat_count = 0
        
        while self.running:
            try:
                if self.clario_login_id and self.clario_loop and not self.clario_loop.is_closed():
                    heartbeat_count += 1
                    print(f"[DEBUG] Sending Clario heartbeat #{heartbeat_count}")
                    
                    # Use the existing event loop from message processor thread
                    future = asyncio.run_coroutine_threadsafe(self.heartbeat(), self.clario_loop)
                    try:
                        success = future.result(timeout=10)  # 10 second timeout
                        if success:
                            print(f"[DEBUG] Heartbeat #{heartbeat_count} successful")
                        else:
                            print(f"[DEBUG] Heartbeat #{heartbeat_count} failed")
                    except Exception as e:
                        print(f"[DEBUG] Heartbeat #{heartbeat_count} failed: {e}")
                        
                elif not self.clario_login_id:
                    print("[DEBUG] Heartbeat skipped - no Clario login_id")
                else:
                    print("[DEBUG] Heartbeat skipped - event loop not available")
                    break  # Exit if event loop becomes unavailable
                
                # Send heartbeat every 30 seconds
                for i in range(30):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                print(f"❌ Heartbeat worker error: {e}")
                time.sleep(10)  # Wait before retry
        
        print("[DEBUG] Clario heartbeat thread stopped")
    
    def message_processor(self):
        """Message processing worker thread."""
        print("[DEBUG] Starting message processor thread...")
        
        # Create event loop for Clario async operations
        self.clario_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.clario_loop)
        print("[DEBUG] Message processor event loop created")
        
        # Authenticate with Clario in this thread's event loop
        if self.clario_credentials:
            print("[DEBUG] Authenticating with Clario in message processor thread...")
            auth_success = self.clario_loop.run_until_complete(self.authenticate_clario_in_thread())
            if not auth_success:
                print("❌ Failed to authenticate with Clario in message processor thread")
                self.clario_loop.close()
                return
        else:
            print("[DEBUG] No Clario credentials provided - Clario functionality disabled")
        
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
                if study_urls:
                    print(f"[DEBUG] Processing {len(study_urls)} study share URL(s)")
                    for url in study_urls:
                        print(f"[DEBUG] Processing URL: {url}")
                        study_info = self.parse_study_share_url(url)
                        if study_info:
                            print(f"[DEBUG] URL parsed successfully, processing study share")
                            # Process study share asynchronously
                            self.clario_loop.run_until_complete(
                                self.process_study_share(message['from'], study_info)
                            )
                        else:
                            print(f"[DEBUG] Failed to parse URL: {url}")
                else:
                    print(f"[DEBUG] No study share URLs detected in message")
                
                self.message_queue.task_done()
                
            except Exception as e:
                print(f"❌ Message processor error: {e}")
        
        # Close Clario client
        if self.clario_tool:
            self.clario_loop.run_until_complete(self.clario_tool.close())
        
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
            print("[DEBUG] XMPP polling thread started")
            
            self.processor_thread = threading.Thread(target=self.message_processor, daemon=True)
            self.processor_thread.start()
            print("[DEBUG] Message processor thread started")
            
            # Start heartbeat thread if we have Clario login
            if self.clario_login_id:
                self.heartbeat_thread = threading.Thread(target=self.heartbeat_worker, daemon=True)
                self.heartbeat_thread.start()
                print("[DEBUG] Clario heartbeat thread started")
            else:
                print("[DEBUG] Clario heartbeat thread skipped - no login_id")
            
            # Main loop with thread monitoring
            while self.running:
                time.sleep(5)  # Check every 5 seconds
                
                # Monitor thread health
                if not self.polling_thread.is_alive():
                    print("❌ XMPP polling thread died!")
                if not self.processor_thread.is_alive():
                    print("❌ Message processor thread died!")
                if self.heartbeat_thread and not self.heartbeat_thread.is_alive():
                    print("❌ Clario heartbeat thread died!")
                
        except KeyboardInterrupt:
            print("\\n[*] Stopping study monitoring...")
            self.running = False
            
            # Wait for threads
            if self.polling_thread and self.polling_thread.is_alive():
                print("[DEBUG] Waiting for XMPP polling thread...")
                self.polling_thread.join(timeout=5)
            
            if self.processor_thread and self.processor_thread.is_alive():
                print("[DEBUG] Waiting for message processor thread...")
                self.processor_thread.join(timeout=5)
            
            if self.heartbeat_thread and self.heartbeat_thread.is_alive():
                print("[DEBUG] Waiting for heartbeat thread...")
                self.heartbeat_thread.join(timeout=5)
            
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
    
    # Store Clario credentials (authentication will happen in message processor thread)
    monitor.set_clario_credentials(clario_username, clario_password)
    
    print("\\n✅ XMPP authenticated, Clario credentials stored!")
    print("[*] Clario authentication will happen in message processor thread")
    
    # Start monitoring
    monitor.start_monitoring()

if __name__ == "__main__":
    main()