#!/usr/bin/env python3
"""
Study Monitor Proof-of-Concept

This script combines XMPP message monitoring with Clario worklist integration
using modern async APIs. When a study share URL is detected in XMPP messages,
it extracts the accession number and looks up detailed patient information from Clario.

Features:
- Async XMPP monitoring using ei_xmpp_api
- Automatic study share URL detection and parsing
- Async Clario integration for patient lookup
- Google Forms link generation with encrypted patient data
- JSON output of patient details (MRN, ULI, DOB, gender)

Architecture:
- Uses ei_xmpp_api for robust XMPP/BOSH communication
- Uses clario_api with SearchBuilder for patient lookups
- Pure async/await architecture throughout
- Automatic connection management and heartbeat handling

Usage:
    python3 study_monitor_poc.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../clario_api'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../ei_xmpp_api'))

import getpass
import base64
import json
import urllib.parse
import asyncio
import signal
from datetime import datetime
from typing import Optional, Dict, Any, List

# Clario API imports
from clario_api import ClarioAPI, setup_logging, get_logger, SearchBuilder, SearchTemplates
from clario_api.models import Study, SearchResult
from clario_api.exceptions import ClarioAPIError, AuthenticationError, NotFoundError, ValidationError

# Enterprise Imaging XMPP API imports
from enterprise_imaging_chat import EnterpriseImagingChat
from enterprise_imaging_chat.models import Message, User, Study as XMPPStudy
from enterprise_imaging_chat.exceptions import (
    EnterpriseImagingError,
    AuthenticationError as XMPPAuthError,
    ConnectionError as XMPPConnectionError,
    MessageError
)
from enterprise_imaging_chat.utils import parse_jid

# === Configuration ===
# Enterprise Imaging XMPP server
EI_SERVER_URL = "https://abpei-hub-app-north.albertahealthservices.ca"

# Clario URL
CLARIO_BASE_URL = "https://worklist.mic.ca"

# Google Forms configuration
XOR_KEY = "micphone"
GOOGLE_FORM_BASE_URL = "https://docs.google.com/forms/d/e/1FAIpQLSe45evjTBqYBDJtcNLp221-QUp91a_KFgJJEZOFKIn4AxtF8g/viewform"

# === Clario API Integration ===

# Set up clario_api logging system
logger = setup_logging(
    level="INFO",
    context={'component': 'study_monitor_poc'},
    mask_sensitive=True
)

# Note: ClarioSearchWrapper removed - now using ClarioAPI directly with async context manager

# Note: RIDManager removed - now using ei_xmpp_api for XMPP management

class StudyMonitorPOC:
    """Integrated XMPP + Clario study monitoring system."""
    
    def __init__(self):
        # XMPP client using ei_xmpp_api
        self.xmpp_client: Optional[EnterpriseImagingChat] = None
        self.running = False
        
        # Clario API client
        self.clario_api = None
    
    # connect_xmpp method removed - now using ei_xmpp_api async context manager in main()
    
    # Note: set_high_priority_presence removed - now handled by ei_xmpp_api in connect_xmpp
    
    async def connect_clario(self, username: str, password: str) -> bool:
        """Connect to Clario API."""
        print(f"[*] Connecting to Clario as: {username}")
        
        try:
            self.clario_api = ClarioAPI(
                base_url=CLARIO_BASE_URL, 
                username=username, 
                password=password,
                log_level="INFO",
                enable_heartbeat=True,
                heartbeat_interval=30.0
            )
            await self.clario_api.connect()
            user_info = await self.clario_api.login()
            
            # Authentication successful - heartbeat is now managed automatically by ClarioAPI
            print(f"[+] Clario connected successfully (login_id={self.clario_api.login_id})")
            
            return True
        except AuthenticationError as e:
            print(f"❌ Clario authentication failed: {e}")
            return False
        except ClarioAPIError as e:
            print(f"❌ Clario API error: {e}")
            return False
        except Exception as e:
            print(f"❌ Clario connection failed: {e}")
            return False
    
    
    # Note: Manual heartbeat method removed - ClarioAPI now manages heartbeat automatically
    
    async def handle_message(self, message: Message) -> None:
        """Handle incoming XMPP messages - mostly for logging since ei_xmpp_api auto-detects study shares."""
        print(f"\n📨 Message from {message.from_jid}: {message.body[:100]}{'...' if len(message.body) > 100 else ''}")
        # ei_xmpp_api automatically detects study share URLs and calls study handlers
        
    async def handle_study_share(self, study: XMPPStudy) -> None:
        """Handle detected study share using ei_xmpp_api Study model."""
        print(f"\n🏥 *** STUDY SHARE DETECTED ***")
        print(f"From: {study.shared_by}")
        print(f"Study UID: {study.study_uid}")
        print(f"Procedure: {study.procedure}")
        
        # Use accession from ei_xmpp_api (already extracted and validated)
        accession = study.accession_number
        logger.debug(f"Using accession from ei_xmpp_api: '{accession}'")
        
        if not accession:
            print("❌ No accession found in study share")
            return
        
        # Process using ei_xmpp_api extracted accession
        await self.process_study_share_unified(study.shared_by, study.study_uid, study.procedure, study.share_url, accession)
    
    async def search_exam_by_accession(self, accession: str) -> List[Study]:
        """Search for exams by accession number using SearchBuilder."""
        logger.info("Searching for exam with accession: %s", accession)
        
        if not self.clario_api or not self.clario_api.login_id:
            raise AuthenticationError("Not logged in - no login ID")
        
        try:
            # Use SearchBuilder for cleaner, more maintainable search
            search = (self.clario_api.search()
                     .advanced()
                     .accession_number(accession)
                     .limit(50)
                     .sort_by("defaultDirectSorting", "DESC"))
            
            # Execute search using the new SearchBuilder interface
            result = await self.clario_api.execute_search(search)
            
            # SearchResult is returned directly from execute_search
            if result.success:
                logger.info("Found %d studies for accession %s", len(result.studies), accession)
                return result.studies
            else:
                logger.warning("Search failed: %s", result.error)
                return []
            
        except ClarioAPIError as e:
            logger.error("Clario API error: %s", e)
            raise
        except Exception as e:
            logger.error("Search error: %s", e)
            raise
    
    async def get_patient_info(self, patient_id: str, exam_id: str) -> Dict[str, Any]:
        """Get detailed patient information using ClarioAPI monitoring endpoint."""
        logger.debug("Fetching patient info for patient_id: %s, exam_id: %s", patient_id, exam_id)
        
        if not self.clario_api:
            raise ClarioAPIError("Clario API not connected")
        
        try:
            # Use clario_api monitoring endpoint only
            patient_info = await self.clario_api.monitoring.get_patient_info(patient_id, exam_id)
            logger.debug("Patient demographics: %s", patient_info)
            return patient_info
                
        except ClarioAPIError as e:
            logger.error("Clario API error getting patient info for patient_id=%s, exam_id=%s: %s", patient_id, exam_id, str(e))
            return {}
        except Exception as e:
            logger.error("Unexpected error getting patient info for patient_id=%s, exam_id=%s: %s", patient_id, exam_id, str(e))
            return {}
    
    async def get_ordering_physician(self, exam_id: str, patient_id: str = None) -> Dict[str, Any]:
        """Get ordering physician details using ClarioAPI monitoring endpoint."""
        logger.debug("Fetching ordering physician for exam_id: %s", exam_id)
        
        if not self.clario_api:
            raise ClarioAPIError("Clario API not connected")
        
        if not patient_id:
            logger.error("patient_id required for monitoring endpoint")
            return {}
        
        try:
            # Use clario_api monitoring endpoint only
            physician_info = await self.clario_api.monitoring.get_ordering_physician(patient_id, exam_id)
            logger.debug("Ordering physician data: %s", physician_info)
            return physician_info
                
        except ClarioAPIError as e:
            logger.error("Clario API error getting ordering physician for exam_id=%s, patient_id=%s: %s", exam_id, patient_id, str(e))
            return {}
        except Exception as e:
            logger.error("Unexpected error getting ordering physician for exam_id=%s, patient_id=%s: %s", exam_id, patient_id, str(e))
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
    
    # extract_username_from_jid() method removed - now using ei_xmpp_api's parse_jid utility
    
    def extract_physician_name(self, ordering_physician_data: Dict[str, Any]) -> str:
        """Extract physician name from ordering physician RPC response."""
        if not ordering_physician_data:
            return ""
        
        # Extract from the known structure: result.values.ordering
        values = ordering_physician_data.get("values", {})
        if values:
            print(f"[DEBUG] Processing ordering physician values: {list(values.keys())}")
        
        ordering_physician = values.get("ordering", "")
        
        if ordering_physician:
            print(f"[DEBUG] Found ordering physician: {ordering_physician}")
            return ordering_physician.strip()
        
        print("[DEBUG] No ordering physician found in values.ordering")
        return ""
    
    async def send_xmpp_reply(self, to_jid: str, message: str) -> bool:
        """Send XMPP reply message using ei_xmpp_api client."""
        if not self.xmpp_client or not self.xmpp_client.is_connected:
            print("[DEBUG] Cannot send reply - no XMPP client or not connected")
            return False
        
        print(f"[DEBUG] Sending XMPP reply to: {to_jid}")
        print(f"[DEBUG] Message length: {len(message)} chars")
        print(f"[DEBUG] Reply message: {message[:150]}{'...' if len(message) > 150 else ''}")
        
        try:
            # Use ei_xmpp_api client to send message
            message_id = await self.xmpp_client.send_message(
                to=to_jid,
                body=message,
                request_receipt=True
            )
            
            print(f"[+] XMPP reply sent successfully to {to_jid}, message_id: {message_id}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send XMPP reply: {e}")
            return False
    
    # Removed manual URL detection - now using ei_xmpp_api's detect_study_share_urls utility
    
    # Removed manual URL parsing - now using ei_xmpp_api's extract_study_info utility
    
    # extract_accession_from_procedure() method removed - now using ei_xmpp_api's robust extraction
    
    async def process_study_share_unified(self, from_jid: str, study_uid: str, procedure: str, share_url: str, accession: str):
        """Unified method to process study shares with patient lookup and Google Forms generation."""
        print(f"\\n🔗 *** PROCESSING STUDY SHARE ***")
        print(f"Accession: {accession}")
        
        # Look up patient details in Clario
        try:
            studies = await self.search_exam_by_accession(accession)
            if studies:
                # Get the first study and extract basic info
                study = studies[0]
                print(f"[+] Found exam in Clario: exam_id={study.exam_id}, patient_id={study.patient_id}")
                
                # Get detailed patient demographics using the correct RPC call
                patient_info = await self.get_patient_info(study.patient_id, study.exam_id)
                
                # Get ordering physician details
                ordering_physician_info = await self.get_ordering_physician(study.exam_id, study.patient_id)
                
                if patient_info:
                    patient_details = {
                        "mrn": patient_info.get("mrn", ""),
                        "uli": study.external_mrn or "",  # Use proper Study model attribute
                        "dob": patient_info.get("dob", ""),  # From patient info RPC
                        "gender": patient_info.get("gender", ""),  # From patient info RPC
                        "patient_name": patient_info.get("name", study.patient_name),  # Prefer full name from patient info
                        "exam_id": study.exam_id,
                        "patient_id": study.patient_id,
                        "ordering_physician": ordering_physician_info,  # Add ordering physician data
                    }
                    print(f"[+] Found complete patient details: {patient_details}")
                else:
                    # Fallback to basic study info if patient info RPC fails
                    patient_details = {
                        "mrn": study.mrn or "",  # Use proper Study model attribute
                        "uli": study.external_mrn or "",  # Use proper Study model attribute
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
                "study_url": share_url,
                "study_uid": study_uid,
                "procedure": procedure
            }
        }
        
        logger.info("Patient lookup result for accession %s", accession)
        logger.debug(json.dumps(output, indent=2))
        
        # Generate Google Forms link and send reply if we have patient details
        if patient_details:
            print("\\n🔗 *** GENERATING GOOGLE FORMS LINK ***")
            
            # Extract username from sender JID using ei_xmpp_api utility
            username = parse_jid(from_jid)["username"]
            
            # Extract physician name from ordering physician data
            ordering_physician = patient_details.get('ordering_physician', {})
            physician = self.extract_physician_name(ordering_physician)
            
            if not physician:
                # No fallback to procedure - use "Unknown Physician" as requested
                physician = "Unknown Physician"
                print(f"[DEBUG] No ordering physician found, using: {physician}")
            else:
                print(f"[DEBUG] Using ordering physician: {physician}")
            
            # Generate encrypted Google Forms link
            try:
                forms_link = self.generate_google_forms_link(patient_details, username, physician)
                
                # Send XMPP reply with the Google Forms link
                reply_message = f"Google Forms link for patient data: {forms_link}"
                success = await self.send_xmpp_reply(from_jid, reply_message)
                
                if success:
                    print("\\n✅ *** GOOGLE FORMS LINK SENT SUCCESSFULLY ***")
                else:
                    print("\\n❌ *** FAILED TO SEND GOOGLE FORMS LINK ***")
                    
            except Exception as e:
                print(f"\\n❌ *** GOOGLE FORMS LINK GENERATION FAILED: {e} ***")
        else:
            print("\\n⚠️  No patient details available - skipping Google Forms link generation")
    
    # Legacy BOSH polling code removed - replaced with ei_xmpp_api async monitoring
    
    # Old polling worker removed - replaced with ei_xmpp_api async message monitoring
    
    # Old message processor thread removed - replaced with ei_xmpp_api async handlers
    
    async def run_monitor(self, poll_interval: float = 2.0):
        """Run the async monitoring system using ei_xmpp_api."""
        print("\\n🚀 *** STARTING STUDY MONITORING ***")
        print("Monitoring XMPP messages for study shares...")
        print("Will automatically lookup patient details in Clario")
        print("Press Ctrl+C to stop")
        
        # Set up signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            print(f"\\n🛑 Received signal {signum}, shutting down gracefully...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Register message and study handlers
        self.xmpp_client.add_message_handler(self.handle_message)
        self.xmpp_client.add_study_handler(self.handle_study_share)
        
        # Start monitoring
        await self.xmpp_client.start_monitoring(poll_interval=poll_interval)
        self.running = True
        
        print("[DEBUG] ei_xmpp_api monitoring started")
        
        # Keep running until signal received
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            self.running = False
        
        # Cleanup
        print("\\n[*] Stopping study monitoring...")
        await self.xmpp_client.stop_monitoring()
        print("[DEBUG] Monitoring stopped")

# === Main Application ===

async def main():
    """Main application entry point using async context managers."""
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
    
    # Configuration
    server_url = EI_SERVER_URL
    poll_interval = float(os.getenv("EI_POLL_INTERVAL", "2.0"))
    
    # Create monitor
    monitor = StudyMonitorPOC()
    
    try:
        # Use ei_xmpp_api async context manager pattern
        monitor.xmpp_client = EnterpriseImagingChat(
            server_url=server_url,
            username=xmpp_username,
            password=xmpp_password,
            log_level="INFO"
        )
        
        async with monitor.xmpp_client:
            print(f"[+] Connected to XMPP as {monitor.xmpp_client.bound_jid}")
            print("[+] High priority presence set automatically by ei_xmpp_api")
            
            # Connect to Clario
            if not await monitor.connect_clario(clario_username, clario_password):
                print("❌ Clario authentication failed")
                return
                
            print("\\n✅ All connections established!")
            
            # Start async monitoring
            await monitor.run_monitor(poll_interval=poll_interval)
            
    except (XMPPAuthError, XMPPConnectionError) as e:
        print(f"❌ XMPP connection failed: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")
        raise
    finally:
        # Cleanup Clario (XMPP cleaned up by context manager)
        if monitor.clario_api:
            await monitor.clario_api.close()
            print("✅ Clario disconnected")

if __name__ == "__main__":
    asyncio.run(main())