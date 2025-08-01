#!/usr/bin/env python3
"""
Clario Search Tool - Single-file application for searching exams and fetching ordering physician details.

This application logs into Clario, searches for exams by accession number,
and retrieves ordering physician information using the Clario API.

Usage:
    python clario_search_tool.py --url https://your-clario-server.com --username your_user --password your_pass --accession ahs123
"""

import asyncio
import aiohttp
import base64
import json
import argparse
import logging
import sys
from typing import Optional, Dict, Any, Union, Tuple, List
from dataclasses import dataclass
from datetime import datetime


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
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
    def from_clario_data(cls, data: Dict[str, Any]) -> 'Study':
        """Create Study from Clario API response data."""
        # Map actual Clario field names based on the real response structure
        return cls(
            exam_id=str(data.get('examID', '')),  # Actual field: examID
            patient_name=data.get('name', ''),   # Actual field: name 
            patient_id=str(data.get('patientID', '')),  # Actual field: patientID
            accession=data.get('accession', ''),  # Actual field: accession
            exam_date=data.get('time', '').split(' ')[0] if data.get('time') else '',  # Parse from 'time' field
            exam_time=data.get('time', '').split(' ', 1)[1] if data.get('time') and ' ' in data.get('time', '') else '',  # Parse from 'time' field
            modality=data.get('group', '').strip(),  # Actual field: group (e.g., " General Radiography")
            priority=data.get('priority', ''),    # Actual field: priority
            status=data.get('status', ''),        # Actual field: status
            description=data.get('procedureName', data.get('siteProcedure', ''))  # Actual fields: procedureName or siteProcedure
        )
    
    def to_dict_with_extras(self) -> Dict[str, Any]:
        """Convert to dict with additional fields for debugging."""
        return {
            **self.__dict__,
            "mrn": getattr(self, '_mrn', ''),
            "external_mrn": getattr(self, '_external_mrn', ''),
            "age": getattr(self, '_age', ''),
            "site": getattr(self, '_site', ''),
            "assigned_to": getattr(self, '_assigned_to', ''),
        }
    
    @classmethod
    def from_clario_data_with_extras(cls, data: Dict[str, Any]) -> 'Study':
        """Create Study with extra fields stored."""
        study = cls.from_clario_data(data)
        
        # Store additional useful fields
        study._mrn = data.get('mrn', '')
        study._external_mrn = data.get('externalMrn', '')
        study._age = data.get('age', '')
        study._site = data.get('site', '')
        study._assigned_to = data.get('assign', '')
        study._rvu = data.get('proRvu', '')
        study._work_unit = data.get('workUnit', '')
        
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
    """Clario search tool for exam lookup and ordering physician retrieval."""
    
    def __init__(self, base_url: str, username: str, password: str):
        """Initialize the Clario search tool."""
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.encoded_password = ClarionPasswordEncoder.encode_password(password)
        self.session: Optional[aiohttp.ClientSession] = None
        self.session_token: Optional[str] = None
        self.transaction_id = 1000  # Starting transaction ID
        
        # Headers for Clario API
        self.headers = {
            "User-Agent": "Clario-Search-Tool/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate"
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
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
                [self.username, self.encoded_password, "", "0"]  # username, encoded_password, site, remember_me
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
            
            # Step 2: Prepare user session (like the original client does)
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
            if isinstance(prepare_response, list) and len(prepare_response) > 0:
                prepare_result = prepare_response[0].get("result", {})
                logger.debug("Session preparation successful")
            else:
                logger.warning("Session preparation returned unexpected format")
            
        else:
            raise Exception(f"Unexpected login response format: {type(response_data)}")
    
    async def search_exam_by_accession(self, accession: str) -> List[Study]:
        """Search for exams by accession number using Clario RPC."""
        logger.info("Searching for exam with accession: %s", accession)
        
        if not self.session_token:
            raise Exception("Not logged in - no session token")
        
        # Build search descriptor using correct ws2 field for accession
        search_descriptor = {
            "params": {
                "input": {
                    "ws2": accession  # Accession number field (confirmed)
                },
                "type": "advanced",
                "isCountOnly": False,
                "limit": None,
            },
            "call": "search/Exam.search",
            "sort": [{"property": "defaultDirectSorting", "direction": "DESC"}],  # Match your example
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
        logger.debug("Search response: %s", json.dumps(response_data, indent=2) if isinstance(response_data, dict) else str(response_data))
        
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
                        logger.debug("Failed exam data: %s", exam_data)
                        
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
    
    async def get_ordering_physician(self, exam_id: str) -> Dict[str, Any]:
        """Get ordering physician details for an exam using Clario RPC."""
        logger.info("Fetching ordering physician for exam ID: %s", exam_id)
        
        if not self.session_token:
            raise Exception("Not logged in - no session token")
        
        # Prepare RPC payload for ordering physician lookup
        rpc_payload = {
            "data": [
                "workflow/patient/Exam.order",
                [exam_id]  # Arguments array with exam ID
            ],
            "tid": self._get_next_transaction_id(),
            "login": int(self.session_token),
            "app": "workflow",
            "action": "rpc",
            "method": "direct",
        }
        
        # Make RPC request
        rpc_url = f"/rpc/app.php?app=workflow&sysClient="
        status_code, response_data, headers = await self._make_request(
            "POST",
            rpc_url,
            json=rpc_payload
        )
        
        logger.info("Ordering physician response received: status=%d", status_code)
        logger.debug("RPC response: %s", json.dumps(response_data, indent=2) if isinstance(response_data, dict) else str(response_data))
        
        order_details = {}
        
        # Parse RPC response
        if isinstance(response_data, list) and len(response_data) > 0:
            result = response_data[0]
            
            if "result" in result:
                order_details = result["result"]
                logger.debug("Successfully retrieved ordering physician data")
            elif "error" in result:
                error_msg = result["error"]
                logger.error("RPC error: %s", error_msg)
                order_details = {"error": error_msg}
            else:
                logger.warning("Unexpected RPC response structure")
                order_details = {"error": "Unexpected response structure", "raw_response": result}
        else:
            logger.error("Invalid RPC response format")
            order_details = {"error": "Invalid response format", "raw_response": response_data}
        
        return order_details
    
    async def search_and_get_details(self, accession: str) -> Dict[str, Any]:
        """Search for exam and get complete details including ordering physician."""
        logger.info("Starting comprehensive search for accession: %s", accession)
        
        # Search for studies
        studies = await self.search_exam_by_accession(accession)
        
        results = {
            "accession": accession,
            "studies_found": len(studies),
            "studies": [],
            "errors": []
        }
        
        # For each study, get ordering physician details
        for study in studies:
            study_result = {
                "study": study.to_dict_with_extras(),
                "ordering_physician": None,
                "error": None
            }
            
            try:
                order_details = await self.get_ordering_physician(study.exam_id)
                study_result["ordering_physician"] = order_details
            except Exception as e:
                error_msg = f"Failed to get ordering physician for exam {study.exam_id}: {e}"
                logger.error(error_msg)
                study_result["error"] = error_msg
                results["errors"].append(error_msg)
            
            results["studies"].append(study_result)
        
        return results


def print_results(results: Dict[str, Any]) -> None:
    """Print search results in a formatted way."""
    print("\n" + "="*80)
    print(f"CLARIO SEARCH RESULTS FOR ACCESSION: {results['accession']}")
    print("="*80)
    
    print(f"\nStudies Found: {results['studies_found']}")
    
    if results['errors']:
        print(f"\nErrors Encountered: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  - {error}")
    
    print("\nDETAILED RESULTS:")
    print("-" * 80)
    
    for i, study_result in enumerate(results['studies'], 1):
        study = study_result['study']
        print(f"\nSTUDY #{i}")
        print(f"  Exam ID: {study['exam_id']}")
        print(f"  Patient Name: {study['patient_name']}")
        print(f"  Patient ID: {study['patient_id']}")
        print(f"  MRN: {study.get('mrn', '')}")
        print(f"  External MRN: {study.get('external_mrn', '')}")
        print(f"  Accession: {study['accession']}")
        print(f"  Exam Date: {study['exam_date']}")
        print(f"  Exam Time: {study['exam_time']}")
        print(f"  Age: {study.get('age', '')}")
        print(f"  Site: {study.get('site', '')}")
        print(f"  Modality: {study['modality']}")
        print(f"  Priority: {study['priority']}")
        print(f"  Status: {study['status']}")
        print(f"  Description: {study['description']}")
        print(f"  Assigned To: {study.get('assigned_to', '')}")
        print(f"  RVU: {getattr(study, '_rvu', study.get('_rvu', ''))}")
        print(f"  Work Unit: {getattr(study, '_work_unit', study.get('_work_unit', ''))}")
        
        print(f"\n  ORDERING PHYSICIAN DETAILS:")
        if study_result['error']:
            print(f"    Error: {study_result['error']}")
        elif study_result['ordering_physician']:
            order_data = study_result['ordering_physician']
            if isinstance(order_data, dict):
                for key, value in order_data.items():
                    print(f"    {key}: {value}")
            else:
                print(f"    Raw Data: {order_data}")
        else:
            print("    No ordering physician data available")
        
        print("-" * 40)


async def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description="Clario Search Tool - Search exams and fetch ordering physician details"
    )
    parser.add_argument("--url", required=True, help="Clario server URL")
    parser.add_argument("--username", required=True, help="Clario username")
    parser.add_argument("--password", required=True, help="Clario password")
    parser.add_argument("--accession", required=True, help="Accession number to search")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        async with ClarionSearchTool(args.url, args.username, args.password) as tool:
            results = await tool.search_and_get_details(args.accession)
            print_results(results)
            
            # Also output JSON for programmatic use
            print("\n\nJSON OUTPUT:")
            print(json.dumps(results, indent=2, default=str))
    
    except Exception as e:
        logger.error("Application failed: %s", e)
        print(f"\nERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
