#!/usr/bin/env python3
"""
RIS (Radiology Information System) Search Client

This script authenticates with Keycloak and queries the RIS search API endpoint
to search for DICOM-related information using the same authentication method
as the XMPP chat client.

Usage:
    python3 ris_search_client.py
"""

import getpass
import requests
import json
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any

# === Configuration ===
RIS_BASE_URL = "https://abpei-hub-app-north.albertahealthservices.ca/ris/web"
RIS_SEARCH_ENDPOINT = f"{RIS_BASE_URL}/v1/searchscreen/query"
CLIENT_ID = "netboot"
TARGET_IDP = "LDAP1"
REALM = "EI"
KEYCLOAK_URL = f"https://abpei-hub-app-north.albertahealthservices.ca/auth/realms/{REALM}/protocol/openid-connect/token?targetIdp={TARGET_IDP}"

# === Data Structure Classes ===

@dataclass
class QuerySearchScreenFilterSetDTO:
    """Filter set for RIS search queries"""
    # This structure is flexible since we don't have the complete Java definition
    filter_type: Optional[str] = None
    field_name: Optional[str] = None
    operator: Optional[str] = None
    value: Optional[str] = None
    values: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values"""
        return {k: v for k, v in asdict(self).items() if v is not None}

@dataclass
class QuerySearchScreenDTO:
    """Main query request structure for RIS search"""
    query_name: str
    query_filter_sets: List[QuerySearchScreenFilterSetDTO]
    optional_fields: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            "queryName": self.query_name,
            "queryFilterSets": [filter_set.to_dict() for filter_set in self.query_filter_sets]
        }
        if self.optional_fields:
            result["optionalFields"] = self.optional_fields
        return result

@dataclass
class QuerySearchResult:
    """Individual search result from RIS"""
    dicom_name: Optional[str] = None
    active: Optional[bool] = None
    code: Optional[str] = None
    name: Optional[str] = None
    dicom_code: Optional[str] = None
    primary_key: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QuerySearchResult':
        """Create from dictionary (JSON response)"""
        return cls(
            dicom_name=data.get('dicomName'),
            active=data.get('active'),
            code=data.get('code'),
            name=data.get('name'),
            dicom_code=data.get('dicomCode'),
            primary_key=data.get('primaryKey')
        )

@dataclass
class QueryResultDTO:
    """Search results container"""
    total: int
    results: List[QuerySearchResult]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'QueryResultDTO':
        """Create from dictionary (JSON response)"""
        results = [QuerySearchResult.from_dict(item) for item in data.get('results', [])]
        return cls(
            total=data.get('total', 0),
            results=results
        )

# === RIS Search Client Class ===

class RISSearchClient:
    """Client for searching the RIS (Radiology Information System) API"""
    
    def __init__(self):
        self.session = requests.Session()
        self.access_token = None
        
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with Keycloak and get access token"""
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
            
            # Set up headers for RIS API requests
            self.session.headers.update({
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Origin": "https://abpei-hub-app-north.albertahealthservices.ca",
                "Referer": "https://abpei-hub-app-north.albertahealthservices.ca/",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin"
            })
            
            return True
            
        except requests.exceptions.HTTPError as e:
            if token_resp.status_code == 401:
                print("❌ Authentication failed - Invalid username/password")
            elif token_resp.status_code == 400:
                print("❌ Bad request - Check if targetIdp=LDAP1 is included in URL")
            else:
                print(f"❌ HTTP Error {token_resp.status_code}: {token_resp.text}")
            return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return False
    
    def search(self, query_request: QuerySearchScreenDTO) -> Optional[QueryResultDTO]:
        """Execute a search query against the RIS API"""
        if not self.access_token:
            print("❌ Not authenticated - call authenticate() first")
            return None
        
        print(f"[*] Executing RIS search query: {query_request.query_name}")
        
        try:
            # Convert query to JSON
            json_payload = query_request.to_dict()
            print(f"[DEBUG] Request payload: {json.dumps(json_payload, indent=2)}")
            
            # Make the API request
            response = self.session.post(RIS_SEARCH_ENDPOINT, json=json_payload)
            response.raise_for_status()
            
            print(f"[+] Search completed successfully")
            print(f"[DEBUG] Response status: {response.status_code}")
            print(f"[DEBUG] Response headers: {dict(response.headers)}")
            
            # Parse response
            response_data = response.json()
            print(f"[DEBUG] Response data: {json.dumps(response_data, indent=2)}")
            
            # Convert to structured result
            result = QueryResultDTO.from_dict(response_data)
            print(f"[+] Found {result.total} results")
            
            return result
            
        except requests.exceptions.HTTPError as e:
            print(f"❌ HTTP Error {response.status_code}: {response.text}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"❌ Request error: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"❌ JSON decode error: {e}")
            print(f"[DEBUG] Raw response: {response.text}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return None
    
    def search_simple(self, query_name: str, filters: Optional[Dict[str, str]] = None, optional_fields: Optional[List[str]] = None) -> Optional[QueryResultDTO]:
        """Simplified search method with dictionary-based filters"""
        filter_sets = []
        
        if filters:
            for field_name, value in filters.items():
                filter_set = QuerySearchScreenFilterSetDTO(
                    field_name=field_name,
                    operator="equals",  # Default operator
                    value=value
                )
                filter_sets.append(filter_set)
        
        query_request = QuerySearchScreenDTO(
            query_name=query_name,
            query_filter_sets=filter_sets,
            optional_fields=optional_fields
        )
        
        return self.search(query_request)

# === Example Usage and Testing ===

def print_results(result: QueryResultDTO):
    """Pretty print search results"""
    print(f"\n📊 *** SEARCH RESULTS ***")
    print(f"Total results: {result.total}")
    
    if result.results:
        print(f"\nResults:")
        for i, item in enumerate(result.results, 1):
            print(f"  [{i}] {item.name or 'N/A'}")
            if item.code:
                print(f"      Code: {item.code}")
            if item.dicom_code:
                print(f"      DICOM Code: {item.dicom_code}")
            if item.dicom_name:
                print(f"      DICOM Name: {item.dicom_name}")
            if item.primary_key:
                print(f"      Primary Key: {item.primary_key}")
            print(f"      Active: {item.active}")
            print()
    else:
        print("No results found.")

def interactive_search():
    """Interactive command-line interface for RIS searching"""
    print("=== RIS Search Client ===")
    
    # Get credentials
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    
    # Create client and authenticate
    client = RISSearchClient()
    if not client.authenticate(username, password):
        return
    
    print("\n[+] Authentication successful!")
    
    while True:
        print("\n--- RIS Search Options ---")
        print("1. Simple search with filters")
        print("2. Advanced search (custom JSON)")
        print("3. Test search examples")
        print("4. Exit")
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == "1":
            # Simple search
            query_name = input("Query name: ").strip()
            if not query_name:
                print("❌ Query name is required")
                continue
            
            print("Enter filters (press Enter with empty field name to finish):")
            filters = {}
            while True:
                field_name = input("Filter field name: ").strip()
                if not field_name:
                    break
                value = input(f"Value for {field_name}: ").strip()
                if value:
                    filters[field_name] = value
            
            # Optional fields
            optional_fields_input = input("Optional fields (comma-separated, or Enter for none): ").strip()
            optional_fields = [f.strip() for f in optional_fields_input.split(",")] if optional_fields_input else None
            
            # Execute search
            result = client.search_simple(query_name, filters, optional_fields)
            if result:
                print_results(result)
        
        elif choice == "2":
            # Advanced search
            print("Enter JSON payload for advanced search:")
            print("Example: {\"queryName\": \"example\", \"queryFilterSets\": [], \"optionalFields\": []}")
            json_input = input("JSON: ").strip()
            
            try:
                json_data = json.loads(json_input)
                # Convert to QuerySearchScreenDTO
                filter_sets = []
                for filter_data in json_data.get("queryFilterSets", []):
                    filter_set = QuerySearchScreenFilterSetDTO(**filter_data)
                    filter_sets.append(filter_set)
                
                query_request = QuerySearchScreenDTO(
                    query_name=json_data["queryName"],
                    query_filter_sets=filter_sets,
                    optional_fields=json_data.get("optionalFields")
                )
                
                result = client.search(query_request)
                if result:
                    print_results(result)
                    
            except json.JSONDecodeError:
                print("❌ Invalid JSON format")
            except KeyError as e:
                print(f"❌ Missing required field: {e}")
        
        elif choice == "3":
            # Test examples
            print("\n🧪 Running test search examples...")
            
            # Example 1: Basic search
            print("\n[TEST 1] Basic query search")
            result = client.search_simple("basic_query", {"status": "active"})
            if result:
                print_results(result)
            
            # Example 2: DICOM search
            print("\n[TEST 2] DICOM-related search")
            result = client.search_simple("dicom_search", {"modality": "CT"}, ["dicomName", "dicomCode"])
            if result:
                print_results(result)
        
        elif choice == "4":
            print("Goodbye!")
            break
        
        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    interactive_search()